# Wireless-Data-Encryption-Decryption
Secure wireless communication system implementing data encryption and decryption using STM32 microcontrollers.
# Secure Wireless Communication System using LoRa and AES-128 Encryption

## Overview

This project presents the design and implementation of a secure long-range wireless communication system using LoRa and AES-128 encryption on STM32 microcontrollers. The system enables confidential message exchange between embedded devices while demonstrating the impact of cryptographic key compromise through a dedicated monitoring node.

The architecture consists of three nodes:

* Alice – Secure transmitting node
* Bob – Secure receiving node
* Darth – Monitoring and attack-simulation node

The project demonstrates how encrypted wireless communication can protect sensitive information and how security is affected when secret key material becomes exposed.


## Key Features

* AES-128 Encryption and Decryption
* Cipher Block Chaining (CBC) Mode
* Dynamic Initialization Vector (IV) Generation
* Long-Range LoRa Communication
* Bluetooth-Based Message Input
* OLED-Based Status and Message Display
* Multi-Block Message Transmission
* Attacker Simulation and Security Demonstration
* STM32 Embedded Firmware Development


## System Architecture

The communication process follows the workflow below:

1. User enters plaintext through Bluetooth terminal.
2. Message is divided into 16-byte blocks.
3. AES-128 CBC encryption is applied.
4. Ciphertext is transmitted through LoRa.
5. Receiver reconstructs packets and decrypts the message.
6. Monitoring node observes encrypted traffic.
7. Post-compromise simulation demonstrates plaintext recovery.

## Hardware Components

| Component                  | Purpose                   |
| -------------------------- | ------------------------- |
| STM32F103C8T6 (Blue Pill)  | Main Controller           |
| SX1278 / RFM95 LoRa Module | Wireless Communication    |
| HC-05 Bluetooth Module     | User Message Input        |
| SSD1306 OLED Display       | Local Display Output      |
| CP2102 USB-UART            | Programming and Debugging |

## Technologies Used

* Embedded C/C++
* Arduino IDE
* STM32 Platform
* LoRa Communication
* AES-128 Cryptography
* Bluetooth Communication
* OLED Interface Programming



## Project Structure

Firmware/
├── alice_device.ino
├── bob_device.ino
└── dart_device.ino

Project_Report/
└── Wireless Data Encryption Decryption.pdf


## Experimental Results

The system successfully demonstrated:

* Secure encrypted communication between embedded nodes
* Reliable multi-block message transfer
* Dynamic ciphertext generation using fresh IVs
* Successful receiver-side plaintext recovery
* Visualization of attacker capabilities before and after key compromise


## Applications

* Secure IoT Communication
* Wireless Sensor Networks
* Industrial Monitoring Systems
* Embedded Security Demonstrators
* Educational Cryptography Platforms
* Long-Range Secure Messaging Systems


## Project Team

* Prithibiraj Brahma
* Rohit Sarkar
* Rituporna Gogoi
* Lakhyajit Boro

Department of Electronics and Communication Engineering
Central Institute of Technology Kokrajhar


## Author Portfolio

GitHub: https://github.com/Thinker145

LinkedIn: https://www.linkedin.com/in/prithibiraj-b-32a689273/
