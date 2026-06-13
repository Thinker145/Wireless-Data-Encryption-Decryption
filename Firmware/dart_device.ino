#include <SPI.h>
#include <LoRa.h>
#include <U8g2lib.h>
#include <AES.h>
#include <string.h>
#include <stdio.h>

#define LORA_FREQUENCY    433E6
#define FAST_LORA_PROFILE 1
#define DEBUG_PORT        Serial1

constexpr uint16_t FRAME_TX_MS       = 1800;
constexpr uint16_t FRAME_LINK_MS     = 1400;
constexpr uint16_t FRAME_AIR_MS      = 1200;
constexpr uint16_t FRAME_AIR_RX_MS   = 1200;
constexpr uint16_t FRAME_DEC_MS      = 1600;
constexpr uint16_t FRAME_XOR_MS      = 1400;
constexpr uint16_t FRAME_RX_MS       = 1800;
constexpr uint16_t FRAME_FINAL_MS    = 2600;
constexpr uint16_t FRAME_LOCKED_MS   = 1700;
constexpr uint16_t FRAME_UNLOCK_MS   = 2400;
constexpr uint16_t FRAME_GAP_MS      = 220;

constexpr uint8_t AES_BLOCK_SIZE = 16;
constexpr size_t MAX_MSG_LEN = 256;
constexpr size_t HEX_BUF_LEN = 64;
constexpr size_t TEXT_BUF_LEN = 24;
constexpr size_t DETAIL_BUF_LEN = 128;
constexpr uint8_t LOGGER_QUEUE_SIZE = 24;
constexpr uint8_t DART_UNLOCK_AFTER_MESSAGES = 5;

enum : uint8_t { PKT_TYPE_START = 0x01, PKT_TYPE_CONT = 0x02 };
enum : uint8_t { FLAG_SECURE = 0x01, FLAG_LAST = 0x02 };

enum VisualPhase : uint8_t {
  PHASE_IDLE = 0,
  PHASE_UNLOCK,
  PHASE_LOCKED_SNIFF,
  PHASE_LOCKED_AIR_TO_RX,
  PHASE_LOCKED_GARBAGE,
  PHASE_SEC_TX,
  PHASE_SEC_LINK,
  PHASE_SEC_TX_TO_AIR,
  PHASE_SEC_AIR_TO_RX,
  PHASE_SEC_DEC,
  PHASE_SEC_XOR,
  PHASE_SEC_RX,
  PHASE_PLAIN_TX,
  PHASE_PLAIN_LINK,
  PHASE_PLAIN_TX_TO_AIR,
  PHASE_PLAIN_AIR_TO_RX,
  PHASE_PLAIN_RX,
  PHASE_FINAL,
  PHASE_GAP
};

byte key[16] = {
  0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
  0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

#define LED_PIN     PC13
#define LORA_CS     PB0
#define LORA_RST    PA8
#define LORA_DIO0   PA1
#define OLED_CLOCK  PB13
#define OLED_DATA   PB15
#define OLED_DC     PA4
#define OLED_RES    PB11
#define OLED_CS     U8X8_PIN_NONE

struct LoggedBlock {
  bool secure;
  bool unlocked;
  bool isFirstBlock;
  bool isLastBlock;
  uint8_t plainLen;
  uint16_t blockIndex;
  byte linkBlock[AES_BLOCK_SIZE];
  byte cipherBlock[AES_BLOCK_SIZE];
  byte preXorBlock[AES_BLOCK_SIZE];
  byte plainBlock[AES_BLOCK_SIZE];
};

AES aes;

U8G2_SSD1306_128X64_NONAME_F_4W_SW_SPI u8g2(
  U8G2_R0, OLED_CLOCK, OLED_DATA, OLED_CS, OLED_DC, OLED_RES
);

byte rx_prev_block[AES_BLOCK_SIZE];
byte cipher_text[AES_BLOCK_SIZE];
byte decrypted_text[AES_BLOCK_SIZE];
byte plain_text[AES_BLOCK_SIZE];

LoggedBlock queueBlocks[LOGGER_QUEUE_SIZE];
uint8_t queueHead = 0;
uint8_t queueTail = 0;
uint8_t queueCount = 0;

LoggedBlock activeBlock;
bool hasActiveBlock = false;
VisualPhase currentPhase = PHASE_IDLE;
unsigned long phaseStartedMs = 0;
bool idleDrawn = false;
bool queueOverflowed = false;
bool dartHasSecrets = false;
char fullMessage[MAX_MSG_LEN + 1] = {0};
size_t fullMessageLen = 0;

uint16_t secureBlockIndex = 0;
uint16_t plainBlockIndex = 0;
uint16_t observedSecureMessages = 0;

bool queueIsFull() {
  return queueCount >= LOGGER_QUEUE_SIZE;
}

bool queueIsEmpty() {
  return queueCount == 0;
}

bool enqueueBlock(const LoggedBlock& block) {
  if (queueIsFull()) return false;

  queueBlocks[queueTail] = block;
  queueTail = (uint8_t)((queueTail + 1) % LOGGER_QUEUE_SIZE);
  queueCount++;
  return true;
}

bool dequeueBlock(LoggedBlock* block) {
  if (queueIsEmpty()) return false;

  *block = queueBlocks[queueHead];
  queueHead = (uint8_t)((queueHead + 1) % LOGGER_QUEUE_SIZE);
  queueCount--;
  return true;
}

void drawWrappedTextArea(const char* msg, int x, int y, int maxWidth, int maxY, int lineHeight) {
  static char lineBuf[MAX_MSG_LEN + 1];

  size_t lineLen = 0;
  const char* p = msg;

  while (*p != '\0' && y <= maxY) {
    if (*p == '\n') {
      lineBuf[lineLen] = '\0';
      u8g2.drawStr(x, y, lineBuf);
      y += lineHeight;
      lineLen = 0;
      p++;
      continue;
    }

    lineBuf[lineLen] = *p;
    lineBuf[lineLen + 1] = '\0';

    if (u8g2.getStrWidth(lineBuf) > maxWidth) {
      lineBuf[lineLen] = '\0';
      if (lineLen == 0) {
        p++;
      } else {
        u8g2.drawStr(x, y, lineBuf);
        y += lineHeight;
      }
      lineLen = 0;
      if (y > maxY) break;
      continue;
    }

    lineLen++;
    p++;
  }

  if (lineLen > 0 && y <= maxY) {
    lineBuf[lineLen] = '\0';
    u8g2.drawStr(x, y, lineBuf);
  }
}

void buildPrintableBlockRows(const byte* src, uint8_t len, char* dst, size_t dstSize) {
  if (dstSize == 0) return;

  size_t out = 0;
  for (uint8_t i = 0; i < len && out < (dstSize - 1); i++) {
    if (i > 0 && (i % 8) == 0 && out < (dstSize - 1)) {
      dst[out++] = '\n';
    }

    char ch = (char)src[i];
    dst[out++] = (ch >= 32 && ch <= 126) ? ch : '.';
  }

  dst[out] = '\0';
}

void buildHexGrouped(const byte* src, uint8_t len, char* dst, size_t dstSize) {
  if (dstSize == 0) return;

  size_t pos = 0;
  for (uint8_t i = 0; i < len && pos < (dstSize - 1); i++) {
    if (i > 0) {
      if ((i % 4) == 0) {
        if (pos < (dstSize - 1)) dst[pos++] = '\n';
      } else {
        if (pos < (dstSize - 1)) dst[pos++] = ' ';
      }
    }

    if (pos + 2 >= dstSize) break;
    int written = snprintf(dst + pos, dstSize - pos, "%02X", src[i]);
    if (written <= 0) break;
    pos += (size_t)written;
  }

  dst[pos] = '\0';
}

void drawNode(int x, const char* label, bool active) {
  const int y = 16;
  const int w = 24;
  const int h = 11;

  u8g2.drawFrame(x, y, w, h);
  if (active) {
    u8g2.drawFrame(x - 1, y - 1, w + 2, h + 2);
  }
  u8g2.drawStr(x + 5, y + 8, label);
}

void drawArrowHead(int xTip) {
  const int y = 21;
  u8g2.drawLine(xTip - 4, y - 3, xTip, y);
  u8g2.drawLine(xTip - 4, y + 3, xTip, y);
}

void drawSegment(int x1, int x2, bool active) {
  const int y = 21;
  if (active) {
    u8g2.drawBox(x1, y - 1, x2 - x1, 3);
  } else {
    u8g2.drawLine(x1, y, x2, y);
  }
}

void drawPacketIcon(int x, bool secure) {
  const int y = 18;
  const int w = 8;
  const int h = 6;

  if (secure) {
    u8g2.drawBox(x, y, w, h);
    u8g2.setDrawColor(0);
    u8g2.drawHLine(x + 2, y + 3, 4);
    u8g2.setDrawColor(1);
  } else {
    u8g2.drawFrame(x, y, w, h);
  }
}

void renderFrame(const char* title,
                 const char* detail,
                 bool activeTx,
                 bool activeAir,
                 bool activeRx,
                 bool activeLeft,
                 bool activeRight,
                 int packetX,
                 bool packetSecure,
                 bool smallFont) {
  u8g2.clearBuffer();

  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 10, title);
  u8g2.drawLine(0, 12, 128, 12);

  drawNode(4, "TX", activeTx);
  drawSegment(28, 52, activeLeft);
  drawArrowHead(52);
  drawNode(52, "AIR", activeAir);
  drawSegment(76, 100, activeRight);
  drawArrowHead(100);
  drawNode(100, "RX", activeRx);

  if (packetX >= 0) {
    drawPacketIcon(packetX, packetSecure);
  }

  u8g2.drawFrame(0, 32, 128, 32);

  if (smallFont) {
    u8g2.setFont(u8g2_font_5x8_tr);
    drawWrappedTextArea(detail, 3, 39, 122, 61, 7);
  } else {
    u8g2.setFont(u8g2_font_6x10_tr);
    drawWrappedTextArea(detail, 3, 41, 122, 61, 10);
  }

  u8g2.sendBuffer();
}

void drawIdleScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_ncenB08_tr);
  u8g2.drawStr(0, 12, "Darth");
  u8g2.drawLine(0, 14, 128, 14);
  u8g2.setFont(u8g2_font_6x10_tr);
  if (queueOverflowed) {
    u8g2.drawStr(0, 30, "Queue overflow");
    u8g2.drawStr(0, 44, "Increase queue");
  } else if (dartHasSecrets) {
    u8g2.drawStr(0, 30, "Secrets stolen");
    u8g2.drawStr(0, 44, "Ready to read");
  } else {
    u8g2.drawStr(0, 30, "Sniffing secure");
    u8g2.drawStr(0, 44, "Need key + IV");
  }
  u8g2.sendBuffer();
}

uint16_t phaseDuration(VisualPhase phase) {
  switch (phase) {
    case PHASE_UNLOCK:          return FRAME_UNLOCK_MS;
    case PHASE_LOCKED_SNIFF:    return FRAME_LOCKED_MS;
    case PHASE_LOCKED_AIR_TO_RX:return FRAME_AIR_RX_MS;
    case PHASE_LOCKED_GARBAGE:  return FRAME_RX_MS;
    case PHASE_SEC_TX:          return FRAME_TX_MS;
    case PHASE_SEC_LINK:        return FRAME_LINK_MS;
    case PHASE_SEC_TX_TO_AIR:   return FRAME_AIR_MS;
    case PHASE_SEC_AIR_TO_RX:   return FRAME_AIR_RX_MS;
    case PHASE_SEC_DEC:         return FRAME_DEC_MS;
    case PHASE_SEC_XOR:         return FRAME_XOR_MS;
    case PHASE_SEC_RX:          return FRAME_RX_MS;
    case PHASE_PLAIN_TX:        return FRAME_TX_MS;
    case PHASE_PLAIN_LINK:      return FRAME_LINK_MS;
    case PHASE_PLAIN_TX_TO_AIR: return FRAME_AIR_MS;
    case PHASE_PLAIN_AIR_TO_RX: return FRAME_AIR_RX_MS;
    case PHASE_PLAIN_RX:        return FRAME_RX_MS;
    case PHASE_FINAL:           return FRAME_FINAL_MS;
    case PHASE_GAP:             return FRAME_GAP_MS;
    case PHASE_IDLE:
    default:
      return 0;
  }
}

void renderActivePhase(unsigned long now) {
  char title[16];
  char detail[DETAIL_BUF_LEN];
  char textBuf[TEXT_BUF_LEN];
  char hexBuf[HEX_BUF_LEN];

  snprintf(title, sizeof(title), "%s B%u",
           activeBlock.secure ? (activeBlock.unlocked ? "SEC" : "DARTH") : "PLN",
           (unsigned)activeBlock.blockIndex);

  unsigned long elapsed = now - phaseStartedMs;
  unsigned long duration = phaseDuration(currentPhase);

  if (currentPhase == PHASE_UNLOCK) {
    renderFrame("DARTH", "Key + IV leaked\nMessages now\nreadable",
                false, false, true, false, false, -1, true, false);
    return;
  }

  if (currentPhase == PHASE_LOCKED_SNIFF) {
    buildHexGrouped(activeBlock.cipherBlock, AES_BLOCK_SIZE, hexBuf, sizeof(hexBuf));
    snprintf(detail, sizeof(detail), "Cipher Sniff\n%s", hexBuf);
    renderFrame(title, detail, false, true, false, false, false, -1, true, true);
    return;
  }

  if (currentPhase == PHASE_LOCKED_AIR_TO_RX) {
    snprintf(detail, sizeof(detail), "No secret key\nMessage unreadable");

    int packetX = 60;
    if (duration > 0) {
      packetX = 60 + (int)(((108 - 60) * elapsed) / duration);
      if (packetX > 108) packetX = 108;
    }

    renderFrame(title, detail, false, elapsed < (duration / 2),
                elapsed >= ((duration * 2) / 3), false, true, packetX, true, false);
    return;
  }

  if (currentPhase == PHASE_LOCKED_GARBAGE) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "RX Garbage\n%s", textBuf);
    renderFrame(title, detail, false, false, true, false, false, -1, true, false);
    return;
  }

  if (currentPhase == PHASE_SEC_TX) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "TX Text\n%s", textBuf);
    renderFrame(title, detail, true, false, false, false, false, -1, true, false);
    return;
  }

  if (currentPhase == PHASE_SEC_LINK) {
    buildHexGrouped(activeBlock.linkBlock, AES_BLOCK_SIZE, hexBuf, sizeof(hexBuf));
    snprintf(detail, sizeof(detail), "%s\n%s",
             activeBlock.isFirstBlock ? "IV" : "Prev Cipher",
             hexBuf);
    renderFrame(title, detail, true, false, false, true, false, -1, true, true);
    return;
  }

  if (currentPhase == PHASE_SEC_TX_TO_AIR) {
    buildHexGrouped(activeBlock.cipherBlock, AES_BLOCK_SIZE, hexBuf, sizeof(hexBuf));
    snprintf(detail, sizeof(detail), "Cipher Text\n%s", hexBuf);

    int packetX = 12;
    if (duration > 0) {
      packetX = 12 + (int)(((60 - 12) * elapsed) / duration);
      if (packetX > 60) packetX = 60;
    }

    renderFrame(title, detail, elapsed < (duration / 3), elapsed >= (duration / 2),
                false, true, false, packetX, true, true);
    return;
  }

  if (currentPhase == PHASE_SEC_AIR_TO_RX) {
    snprintf(detail, sizeof(detail), "LoRa transfer\nEncrypted block");

    int packetX = 60;
    if (duration > 0) {
      packetX = 60 + (int)(((108 - 60) * elapsed) / duration);
      if (packetX > 108) packetX = 108;
    }

    renderFrame(title, detail, false, elapsed < (duration / 2),
                elapsed >= ((duration * 2) / 3), false, true, packetX, true, false);
    return;
  }

  if (currentPhase == PHASE_SEC_DEC) {
    buildHexGrouped(activeBlock.preXorBlock, AES_BLOCK_SIZE, hexBuf, sizeof(hexBuf));
    snprintf(detail, sizeof(detail), "AES Dec Out\n%s\nAwaiting XOR", hexBuf);
    renderFrame(title, detail, false, false, true, false, false, -1, true, true);
    return;
  }

  if (currentPhase == PHASE_SEC_XOR) {
    snprintf(detail, sizeof(detail), "%s\nReveal plain text",
             activeBlock.isFirstBlock ? "XOR with IV" : "XOR with Prev CT");
    renderFrame(title, detail, false, false, true, false, false, -1, true, false);
    return;
  }

  if (currentPhase == PHASE_SEC_RX) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "RX Text\n%s", textBuf);
    renderFrame(title, detail, false, false, true, false, false, -1, true, false);
    return;
  }

  if (currentPhase == PHASE_PLAIN_TX) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "TX Text\n%s", textBuf);
    renderFrame(title, detail, true, false, false, false, false, -1, false, false);
    return;
  }

  if (currentPhase == PHASE_PLAIN_LINK) {
    snprintf(detail, sizeof(detail), "No encryption\nOpen text");
    renderFrame(title, detail, true, false, false, true, false, -1, false, false);
    return;
  }

  if (currentPhase == PHASE_PLAIN_TX_TO_AIR) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "Plain Data\n%s", textBuf);

    int packetX = 12;
    if (duration > 0) {
      packetX = 12 + (int)(((60 - 12) * elapsed) / duration);
      if (packetX > 60) packetX = 60;
    }

    renderFrame(title, detail, elapsed < (duration / 3), elapsed >= (duration / 2),
                false, true, false, packetX, false, false);
    return;
  }

  if (currentPhase == PHASE_PLAIN_AIR_TO_RX) {
    snprintf(detail, sizeof(detail), "LoRa transfer\nPlain packet");

    int packetX = 60;
    if (duration > 0) {
      packetX = 60 + (int)(((108 - 60) * elapsed) / duration);
      if (packetX > 108) packetX = 108;
    }

    renderFrame(title, detail, false, elapsed < (duration / 2),
                elapsed >= ((duration * 2) / 3), false, true, packetX, false, false);
    return;
  }

  if (currentPhase == PHASE_PLAIN_RX) {
    buildPrintableBlockRows(activeBlock.plainBlock, activeBlock.plainLen, textBuf, sizeof(textBuf));
    snprintf(detail, sizeof(detail), "RX Text\n%s", textBuf);
    renderFrame(title, detail, false, false, true, false, false, -1, false, false);
    return;
  }

  if (currentPhase == PHASE_FINAL) {
    snprintf(title, sizeof(title), "%s MSG", activeBlock.secure ? "SEC" : "PLN");
    snprintf(detail, sizeof(detail), "RX Full\n%s", fullMessage);
    renderFrame(title, detail, false, false, true, false, false, -1, activeBlock.secure, false);
    return;
  }

  if (currentPhase == PHASE_GAP) {
    u8g2.clearBuffer();
    u8g2.sendBuffer();
    return;
  }
}

void decryptLoggedBlock(LoggedBlock* block) {
  if (!block->secure || block->unlocked) return;

  aes.decrypt(block->cipherBlock, block->preXorBlock);
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
    block->plainBlock[i] = block->preXorBlock[i] ^ block->linkBlock[i];
  }
  block->unlocked = true;
}

void startNextAnimation(unsigned long now) {
  if (!dequeueBlock(&activeBlock)) {
    hasActiveBlock = false;
    currentPhase = PHASE_IDLE;
    return;
  }

  if (dartHasSecrets) {
    decryptLoggedBlock(&activeBlock);
  }

  hasActiveBlock = true;
  if (activeBlock.isFirstBlock && (!activeBlock.secure || activeBlock.unlocked)) {
    fullMessageLen = 0;
    fullMessage[0] = '\0';
  }
  if (!activeBlock.secure || activeBlock.unlocked) {
    for (uint8_t i = 0; i < activeBlock.plainLen && fullMessageLen < MAX_MSG_LEN; i++) {
      fullMessage[fullMessageLen++] = (char)activeBlock.plainBlock[i];
    }
    fullMessage[fullMessageLen] = '\0';
  }
  if (activeBlock.secure) {
    currentPhase = activeBlock.unlocked ? PHASE_SEC_TX : PHASE_LOCKED_SNIFF;
  } else {
    currentPhase = PHASE_PLAIN_TX;
  }
  phaseStartedMs = now;
  idleDrawn = false;
}

void advancePhase(unsigned long now) {
  switch (currentPhase) {
    case PHASE_UNLOCK:
      hasActiveBlock = false;
      currentPhase = PHASE_IDLE;
      break;
    case PHASE_LOCKED_SNIFF:
      currentPhase = PHASE_LOCKED_AIR_TO_RX;
      break;
    case PHASE_LOCKED_AIR_TO_RX:
      currentPhase = PHASE_LOCKED_GARBAGE;
      break;
    case PHASE_LOCKED_GARBAGE:
      if (activeBlock.isLastBlock) {
        observedSecureMessages++;
        if (observedSecureMessages >= DART_UNLOCK_AFTER_MESSAGES) {
          dartHasSecrets = true;
          currentPhase = PHASE_UNLOCK;
          DEBUG_PORT.println("Darth breach simulated: key + IV leaked");
        } else {
          currentPhase = PHASE_GAP;
        }
      } else {
        currentPhase = PHASE_GAP;
      }
      break;
    case PHASE_SEC_TX:
      currentPhase = PHASE_SEC_LINK;
      break;
    case PHASE_SEC_LINK:
      currentPhase = PHASE_SEC_TX_TO_AIR;
      break;
    case PHASE_SEC_TX_TO_AIR:
      currentPhase = PHASE_SEC_AIR_TO_RX;
      break;
    case PHASE_SEC_AIR_TO_RX:
      currentPhase = PHASE_SEC_DEC;
      break;
    case PHASE_SEC_DEC:
      currentPhase = PHASE_SEC_XOR;
      break;
    case PHASE_SEC_XOR:
      currentPhase = PHASE_SEC_RX;
      break;
    case PHASE_SEC_RX:
      currentPhase = activeBlock.isLastBlock ? PHASE_FINAL : PHASE_GAP;
      break;
    case PHASE_PLAIN_TX:
      currentPhase = PHASE_PLAIN_LINK;
      break;
    case PHASE_PLAIN_LINK:
      currentPhase = PHASE_PLAIN_TX_TO_AIR;
      break;
    case PHASE_PLAIN_TX_TO_AIR:
      currentPhase = PHASE_PLAIN_AIR_TO_RX;
      break;
    case PHASE_PLAIN_AIR_TO_RX:
      currentPhase = PHASE_PLAIN_RX;
      break;
    case PHASE_PLAIN_RX:
      currentPhase = activeBlock.isLastBlock ? PHASE_FINAL : PHASE_GAP;
      break;
    case PHASE_FINAL:
      currentPhase = PHASE_GAP;
      break;
    case PHASE_GAP:
      hasActiveBlock = false;
      currentPhase = PHASE_IDLE;
      break;
    case PHASE_IDLE:
    default:
      break;
  }

  phaseStartedMs = now;
}

void updateAnimation() {
  unsigned long now = millis();

  if (!hasActiveBlock) {
    if (currentPhase == PHASE_UNLOCK) {
      renderActivePhase(now);
      if ((now - phaseStartedMs) >= phaseDuration(currentPhase)) {
        advancePhase(now);
      }
    } else if (!queueIsEmpty()) {
      startNextAnimation(now);
    } else if (!idleDrawn) {
      drawIdleScreen();
      idleDrawn = true;
    }
    return;
  }

  renderActivePhase(now);

  uint16_t duration = phaseDuration(currentPhase);
  if (duration > 0 && (now - phaseStartedMs) >= duration) {
    advancePhase(now);
  }
}

void capturePackets() {
  while (true) {
    int packetSize = LoRa.parsePacket();
    if (packetSize < 3) break;

    LoggedBlock block;
    memset(&block, 0, sizeof(block));

    uint8_t packetType = (uint8_t)LoRa.read();
    uint8_t flags = (uint8_t)LoRa.read();
    uint8_t chunkLen = (uint8_t)LoRa.read();

    bool pktSecure = (flags & FLAG_SECURE) != 0;
    bool isLast = (flags & FLAG_LAST) != 0;
    block.secure = pktSecure;
    block.unlocked = !pktSecure || dartHasSecrets;
    block.isFirstBlock = (packetType == PKT_TYPE_START);
    block.isLastBlock = isLast;
    block.plainLen = (chunkLen > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : chunkLen;

    if (packetType == PKT_TYPE_START) {
      memset(rx_prev_block, 0, AES_BLOCK_SIZE);
      secureBlockIndex = 0;
      plainBlockIndex = 0;
    }

    if (pktSecure) {
      if (block.isFirstBlock) {
        uint8_t ivGot = 0;
        while (LoRa.available() && ivGot < AES_BLOCK_SIZE) {
          block.linkBlock[ivGot++] = (byte)LoRa.read();
        }
        if (ivGot != AES_BLOCK_SIZE) {
          while (LoRa.available()) LoRa.read();
          DEBUG_PORT.println("Darth: short IV");
          continue;
        }
      } else {
        memcpy(block.linkBlock, rx_prev_block, AES_BLOCK_SIZE);
      }

      uint8_t got = 0;
      while (LoRa.available() && got < AES_BLOCK_SIZE) {
        cipher_text[got++] = (byte)LoRa.read();
      }
      while (LoRa.available()) LoRa.read();

      if (got != AES_BLOCK_SIZE) {
        DEBUG_PORT.println("Darth: short secure block");
        continue;
      }

      memcpy(block.cipherBlock, cipher_text, AES_BLOCK_SIZE);

      if (block.unlocked) {
        aes.decrypt(cipher_text, decrypted_text);
        for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
          plain_text[i] = decrypted_text[i] ^ block.linkBlock[i];
        }

        memcpy(block.preXorBlock, decrypted_text, AES_BLOCK_SIZE);
        memcpy(block.plainBlock, plain_text, AES_BLOCK_SIZE);
      } else {
        memset(block.preXorBlock, 0, AES_BLOCK_SIZE);
        memset(block.plainBlock, 0, AES_BLOCK_SIZE);
        for (uint8_t i = 0; i < block.plainLen; i++) {
          char rawChar = (char)cipher_text[i];
          block.plainBlock[i] = (byte)((rawChar >= 32 && rawChar <= 126) ? rawChar : '.');
        }
      }
      memcpy(rx_prev_block, cipher_text, AES_BLOCK_SIZE);

      secureBlockIndex++;
      block.blockIndex = secureBlockIndex;
    } else {
      uint8_t got = 0;
      while (LoRa.available() && got < block.plainLen) {
        plain_text[got++] = (byte)LoRa.read();
      }
      while (LoRa.available()) LoRa.read();

      memset(block.plainBlock, 0, AES_BLOCK_SIZE);
      memcpy(block.plainBlock, plain_text, got);
      block.plainLen = got;
      plainBlockIndex++;
      block.blockIndex = plainBlockIndex;
    }

    if (!enqueueBlock(block)) {
      queueOverflowed = true;
      DEBUG_PORT.println("Darth: queue full, dropping block");
    } else {
      DEBUG_PORT.print("Darth queued ");
      DEBUG_PORT.print(block.secure ? "SEC" : "PLN");
      DEBUG_PORT.print(" block ");
      DEBUG_PORT.print(block.blockIndex);
      DEBUG_PORT.print(" | queueCount=");
      DEBUG_PORT.println(queueCount);
      idleDrawn = false;
    }
  }
}

void setup() {
  DEBUG_PORT.begin(115200);

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);

  pinMode(OLED_RES, OUTPUT);
  digitalWrite(OLED_RES, LOW);
  delay(20);
  digitalWrite(OLED_RES, HIGH);
  delay(20);

  u8g2.begin();
  u8g2.setPowerSave(0);
  u8g2.setContrast(255);

  aes.set_key(key, 16);

  LoRa.setPins(LORA_CS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQUENCY)) {
    DEBUG_PORT.println("LoRa Init Failed!");
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 20, "Darth Error");
    u8g2.drawStr(0, 40, "Check LoRa wiring");
    u8g2.sendBuffer();
    while (1) {}
  }

#if FAST_LORA_PROFILE
  LoRa.setSpreadingFactor(7);
  LoRa.setSignalBandwidth(250E3);
  LoRa.setCodingRate4(5);
#endif

  LoRa.enableCrc();

  memset(rx_prev_block, 0, AES_BLOCK_SIZE);

  DEBUG_PORT.println("Darth online.");
  drawIdleScreen();
}

void loop() {
  capturePackets();
  updateAnimation();
}
