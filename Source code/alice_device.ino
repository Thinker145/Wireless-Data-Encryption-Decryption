#include <SPI.h>
#include <LoRa.h>
#include <U8g2lib.h>
#include <AES.h>
#include <string.h>
#include <stdio.h>

HardwareSerial BTSerial(PA3, PA2);

#define LORA_FREQUENCY    433E6
#define FAST_LORA_PROFILE 1
#define DEBUG_PORT        Serial1
#define BT_PORT           BTSerial

constexpr uint32_t BT_BAUD = 9600;
constexpr char DEVICE_NAME[] = "Alice";

constexpr uint16_t TX_MESSAGE_HOLD_MS    = 2200;
constexpr uint16_t TX_BLOCK_TEXT_HOLD_MS = 1500;
constexpr uint16_t TX_CIPHER_HOLD_MS     = 1800;
constexpr uint16_t TX_PLAIN_HOLD_MS      = 1500;
constexpr uint16_t TX_POST_PACKET_MS     = 120;

constexpr uint8_t AES_BLOCK_SIZE = 16;
constexpr size_t MAX_MSG_LEN = 256;
constexpr uint16_t DISPLAY_UPDATE_MS = 120;
constexpr size_t TX_HEX_BUF_LEN = 36;
constexpr size_t TX_TEXT_BUF_LEN = 20;

enum : uint8_t { PKT_TYPE_START = 0x01, PKT_TYPE_CONT = 0x02 };
enum : uint8_t { FLAG_SECURE = 0x01, FLAG_LAST = 0x02 };

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

AES aes;

U8G2_SSD1306_128X64_NONAME_F_4W_SW_SPI u8g2(
  U8G2_R0, OLED_CLOCK, OLED_DATA, OLED_CS, OLED_DC, OLED_RES
);

byte plain_text[AES_BLOCK_SIZE];
byte cipher_text[AES_BLOCK_SIZE];
byte decrypted_text[AES_BLOCK_SIZE];
byte tx_message_iv[AES_BLOCK_SIZE];
byte tx_prev_block[AES_BLOCK_SIZE];
byte rx_prev_block[AES_BLOCK_SIZE];

char serial_buffer[MAX_MSG_LEN + 1] = {0};
size_t serial_len = 0;

char rx_buffer[MAX_MSG_LEN + 1] = {0};
size_t rx_len = 0;

bool rx_active = false;
bool tx_busy = false;
bool message_ready = false;
unsigned long last_display_ms = 0;
uint32_t g_message_counter = 0;

void handleInputFrom(Stream& port);

void generateMessageIV(byte* iv) {
  uint32_t seed = (uint32_t)micros()
    ^ ((uint32_t)millis() << 10)
    ^ (++g_message_counter * 0x9E3779B9UL);

  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    iv[i] = (byte)(seed & 0xFF);
    seed += (0xA5A5A5A5UL + i);
  }
}

void displayMessage(const char* title, const char* msg) {
  static char lineBuf[MAX_MSG_LEN + 1];

  const int textX = 0;
  const int titleY = 12;
  const int dividerY = 14;
  const int textStartY = 26;
  const int lineHeight = 10;
  const int maxTextWidth = 128;
  const int maxTextY = 62;

  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_ncenB08_tr);
  u8g2.drawStr(0, titleY, title);
  u8g2.drawLine(0, dividerY, 128, dividerY);
  u8g2.setFont(u8g2_font_6x10_tr);

  int y = textStartY;
  size_t lineLen = 0;
  const char* p = msg;

  while (*p != '\0' && y <= maxTextY) {
    if (*p == '\n') {
      lineBuf[lineLen] = '\0';
      u8g2.drawStr(textX, y, lineBuf);
      y += lineHeight;
      lineLen = 0;
      p++;
      continue;
    }

    lineBuf[lineLen] = *p;
    lineBuf[lineLen + 1] = '\0';

    if (u8g2.getStrWidth(lineBuf) > maxTextWidth) {
      lineBuf[lineLen] = '\0';
      if (lineLen == 0) {
        p++;
      } else {
        u8g2.drawStr(textX, y, lineBuf);
        y += lineHeight;
      }
      lineLen = 0;
      continue;
    }

    lineLen++;
    p++;
  }

  if (lineLen > 0 && y <= maxTextY) {
    lineBuf[lineLen] = '\0';
    u8g2.drawStr(textX, y, lineBuf);
  }

  u8g2.sendBuffer();
}

void btPrintStatus() {
  BT_PORT.print(DEVICE_NAME);
  BT_PORT.println(" AES-CBC ready.");
}

void responsiveDelay(uint16_t holdMs) {
  unsigned long startMs = millis();
  while ((millis() - startMs) < holdMs) {
    handleInputFrom(DEBUG_PORT);
    handleInputFrom(BT_PORT);
    delay(5);
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

void buildCipherHex(const byte* src, char* dst, size_t dstSize) {
  if (dstSize == 0) return;

  size_t pos = 0;
  for (uint8_t i = 0; i < AES_BLOCK_SIZE && pos < (dstSize - 1); i++) {
    if (i == 8 && pos < (dstSize - 1)) {
      dst[pos++] = '\n';
    }

    if (pos + 2 >= dstSize) break;
    int written = snprintf(dst + pos, dstSize - pos, "%02X", src[i]);
    if (written <= 0) break;
    pos += (size_t)written;
  }

  dst[pos] = '\0';
}

void showTxTextBlock(const byte* src, uint8_t len, uint16_t blockIndex, uint16_t totalBlocks) {
  char title[24];
  char textBuf[TX_TEXT_BUF_LEN];

  snprintf(title, sizeof(title), "Tx Text %u/%u",
           (unsigned)blockIndex, (unsigned)totalBlocks);
  buildPrintableBlockRows(src, len, textBuf, sizeof(textBuf));
  displayMessage(title, textBuf);
}

void showTxCipherBlock(const byte* src, uint16_t blockIndex, uint16_t totalBlocks) {
  char title[24];
  char hexBuf[TX_HEX_BUF_LEN];

  snprintf(title, sizeof(title), "Tx Cipher %u/%u",
           (unsigned)blockIndex, (unsigned)totalBlocks);
  buildCipherHex(src, hexBuf, sizeof(hexBuf));
  displayMessage(title, hexBuf);
}

void drawIdleScreen() {
  displayMessage(DEVICE_NAME, "AES-CBC\nReady");
}

void appendToRx(const byte* data, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    if (rx_len >= MAX_MSG_LEN) break;
    rx_buffer[rx_len++] = (char)data[i];
  }
  rx_buffer[rx_len] = '\0';
}

void updateRxDisplay(bool force) {
  unsigned long now = millis();
  if (!force && (now - last_display_ms < DISPLAY_UPDATE_MS)) return;

  displayMessage("Rx Message:", rx_buffer);
  last_display_ms = now;
}

void resetRxMessage() {
  rx_active = true;
  rx_len = 0;
  rx_buffer[0] = '\0';
  memset(rx_prev_block, 0, AES_BLOCK_SIZE);

  DEBUG_PORT.println();
  DEBUG_PORT.print("Rx: ");
}

void sendPacket(const char* message, size_t msgLen) {
  if (msgLen == 0) return;

  const bool secure = true;
  tx_busy = true;

  DEBUG_PORT.print("Sending ");
  DEBUG_PORT.print(msgLen);
  DEBUG_PORT.println(" bytes...");
  BT_PORT.print(DEVICE_NAME);
  BT_PORT.print(" Sending: ");
  BT_PORT.println(message);

  digitalWrite(LED_PIN, LOW);
  if (secure) {
    generateMessageIV(tx_message_iv);
    memcpy(tx_prev_block, tx_message_iv, AES_BLOCK_SIZE);
  } else {
    memset(tx_message_iv, 0, AES_BLOCK_SIZE);
    memset(tx_prev_block, 0, AES_BLOCK_SIZE);
  }

  displayMessage("Tx Secure", message);
  responsiveDelay(TX_MESSAGE_HOLD_MS);

  size_t offset = 0;
  uint16_t blockIndex = 0;
  uint16_t totalBlocks = (msgLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

  while (offset < msgLen) {
    uint8_t chunkLen = (msgLen - offset > AES_BLOCK_SIZE)
      ? AES_BLOCK_SIZE
      : (uint8_t)(msgLen - offset);

    bool isLast = (offset + chunkLen >= msgLen);
    uint8_t pktType = (offset == 0) ? PKT_TYPE_START : PKT_TYPE_CONT;
    uint8_t flags = (secure ? FLAG_SECURE : 0) | (isLast ? FLAG_LAST : 0);

    memset(plain_text, 0, AES_BLOCK_SIZE);
    memcpy(plain_text, message + offset, chunkLen);
    blockIndex++;

    if (secure) {
      showTxTextBlock(plain_text, chunkLen, blockIndex, totalBlocks);
      responsiveDelay(TX_BLOCK_TEXT_HOLD_MS);

      for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
        plain_text[i] ^= tx_prev_block[i];
      }

      aes.encrypt(plain_text, cipher_text);
      memcpy(tx_prev_block, cipher_text, AES_BLOCK_SIZE);

      showTxCipherBlock(cipher_text, blockIndex, totalBlocks);
      responsiveDelay(TX_CIPHER_HOLD_MS);
    }

    DEBUG_PORT.print("TX Block ");
    DEBUG_PORT.print(blockIndex);
    DEBUG_PORT.print("/");
    DEBUG_PORT.print(totalBlocks);
    DEBUG_PORT.print(" | chunkLen=");
    DEBUG_PORT.print(chunkLen);
    DEBUG_PORT.print(" | type=");
    DEBUG_PORT.print(pktType == PKT_TYPE_START ? "START" : "CONT");
    DEBUG_PORT.print(" | mode=");
    DEBUG_PORT.println(secure ? "SECURE" : "PLAIN");
    if (secure && pktType == PKT_TYPE_START) {
      DEBUG_PORT.print("TX IV: ");
      for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
        if (i == 8) DEBUG_PORT.print(" ");
        if (tx_message_iv[i] < 0x10) DEBUG_PORT.print("0");
        DEBUG_PORT.print(tx_message_iv[i], HEX);
      }
      DEBUG_PORT.println();
    }

    LoRa.beginPacket();
    LoRa.write(pktType);
    LoRa.write(flags);
    LoRa.write(chunkLen);

    if (secure) {
      if (pktType == PKT_TYPE_START) {
        LoRa.write(tx_message_iv, AES_BLOCK_SIZE);
      }
      LoRa.write(cipher_text, AES_BLOCK_SIZE);
    } else {
      LoRa.write(plain_text, chunkLen);
    }

    LoRa.endPacket();

    offset += chunkLen;
    responsiveDelay(TX_POST_PACKET_MS);
  }

  digitalWrite(LED_PIN, HIGH);
  DEBUG_PORT.println("Sent.");
  BT_PORT.println("Sent.");
  tx_busy = false;
  drawIdleScreen();
}

void checkReceive() {
  int packetSize = LoRa.parsePacket();
  if (packetSize < 3) return;

  uint8_t packetType = (uint8_t)LoRa.read();
  uint8_t flags = (uint8_t)LoRa.read();
  uint8_t chunkLen = (uint8_t)LoRa.read();

  bool pktSecure = (flags & FLAG_SECURE) != 0;
  bool isLast = (flags & FLAG_LAST) != 0;
  DEBUG_PORT.print("RX Packet | type=");
  DEBUG_PORT.print(packetType == PKT_TYPE_START ? "START" : "CONT");
  DEBUG_PORT.print(" | chunkLen=");
  DEBUG_PORT.print(chunkLen);
  DEBUG_PORT.print(" | pktMode=");
  DEBUG_PORT.print(pktSecure ? "SECURE" : "PLAIN");
  DEBUG_PORT.println(" | localMode=SECURE");

  if (packetType == PKT_TYPE_START) {
    resetRxMessage();
  } else if (!rx_active || packetType != PKT_TYPE_CONT) {
    while (LoRa.available()) LoRa.read();
    return;
  }

  if (pktSecure) {
    if (chunkLen > AES_BLOCK_SIZE) chunkLen = AES_BLOCK_SIZE;

    if (packetType == PKT_TYPE_START) {
      uint8_t ivGot = 0;
      while (LoRa.available() && ivGot < AES_BLOCK_SIZE) {
        rx_prev_block[ivGot++] = (byte)LoRa.read();
      }
      if (ivGot != AES_BLOCK_SIZE) {
        while (LoRa.available()) LoRa.read();
        rx_active = false;
        DEBUG_PORT.println("\nRx aborted: short IV");
        drawIdleScreen();
        return;
      }
    }

    uint8_t got = 0;
    while (LoRa.available() && got < AES_BLOCK_SIZE) {
      cipher_text[got++] = (byte)LoRa.read();
    }
    while (LoRa.available()) LoRa.read();

    if (got != AES_BLOCK_SIZE) {
      rx_active = false;
      DEBUG_PORT.println("\nRx aborted: short secure block");
      drawIdleScreen();
      return;
    }

    aes.decrypt(cipher_text, decrypted_text);

    for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
      decrypted_text[i] ^= rx_prev_block[i];
    }
    memcpy(rx_prev_block, cipher_text, AES_BLOCK_SIZE);

    appendToRx(decrypted_text, chunkLen);

    DEBUG_PORT.print("RX Secure Append | chunk='");
    for (uint8_t i = 0; i < chunkLen; i++) {
      DEBUG_PORT.write((char)decrypted_text[i]);
    }
    DEBUG_PORT.println("'");
    DEBUG_PORT.print("RX Buffer Now: ");
    DEBUG_PORT.println(rx_buffer);

    for (uint8_t i = 0; i < chunkLen; i++) {
      DEBUG_PORT.write((char)decrypted_text[i]);
    }

    updateRxDisplay(isLast);

    if (isLast) {
      BT_PORT.print(DEVICE_NAME);
      BT_PORT.print(" Rx Message: ");
      BT_PORT.println(rx_buffer);
      DEBUG_PORT.println();
      rx_active = false;
    }
    return;
  }

  if (chunkLen > AES_BLOCK_SIZE) chunkLen = AES_BLOCK_SIZE;

  uint8_t got = 0;
  while (LoRa.available() && got < chunkLen) {
    plain_text[got] = (byte)LoRa.read();
    DEBUG_PORT.write((char)plain_text[got]);
    got++;
  }
  while (LoRa.available()) LoRa.read();

  appendToRx(plain_text, got);

  DEBUG_PORT.print("RX Plain Append | chunk='");
  for (uint8_t i = 0; i < got; i++) {
    DEBUG_PORT.write((char)plain_text[i]);
  }
  DEBUG_PORT.println("'");
  DEBUG_PORT.print("RX Buffer Now: ");
  DEBUG_PORT.println(rx_buffer);

  updateRxDisplay(isLast);

  if (isLast) {
    BT_PORT.print(DEVICE_NAME);
    BT_PORT.print(" Rx Message: ");
    BT_PORT.println(rx_buffer);
    DEBUG_PORT.println();
    rx_active = false;
  }
}

void processInputChar(char inChar) {
  if (inChar == '\n' || inChar == '\r') {
    if (serial_len > 0) {
      message_ready = true;
    }
    return;
  }

  if (!message_ready && serial_len < MAX_MSG_LEN) {
    serial_buffer[serial_len++] = inChar;
    serial_buffer[serial_len] = '\0';
  }
}

void handleInputFrom(Stream& port) {
  while (port.available() > 0) {
    processInputChar((char)port.read());
  }
}

void sendQueuedMessage() {
  if (!message_ready || tx_busy) return;

  char outbound[MAX_MSG_LEN + 1];
  size_t outboundLen = serial_len;
  memcpy(outbound, serial_buffer, outboundLen + 1);

  message_ready = false;
  serial_len = 0;
  serial_buffer[0] = '\0';

  sendPacket(outbound, outboundLen);
}

void setup() {
  DEBUG_PORT.begin(115200);
  BT_PORT.begin(BT_BAUD);

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
    displayMessage("Error", "Check LoRa wiring");
    while (1) {}
  }

#if FAST_LORA_PROFILE
  LoRa.setSpreadingFactor(7);
  LoRa.setSignalBandwidth(250E3);
  LoRa.setCodingRate4(5);
#endif

  LoRa.enableCrc();

  DEBUG_PORT.print(DEVICE_NAME);
  DEBUG_PORT.println(" ready.");
  BT_PORT.print(DEVICE_NAME);
  BT_PORT.println(" Bluetooth ready.");
  BT_PORT.println("Type a message and send newline.");
  drawIdleScreen();
  btPrintStatus();
}

void loop() {
  checkReceive();
  handleInputFrom(DEBUG_PORT);
  handleInputFrom(BT_PORT);
  sendQueuedMessage();
}
