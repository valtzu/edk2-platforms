/** @file
 *
 *  Copyright (c) 2019, ARM Limited. All rights reserved.
 *  Copyright (c) 2017 - 2020, Andrei Warkentin <andrey.warkentin@gmail.com>
 *  Copyright (c) 2016, Linaro Limited. All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 **/

#ifndef __RASPBERRY_PI_FIRMWARE_PROTOCOL_H__
#define __RASPBERRY_PI_FIRMWARE_PROTOCOL_H__

#define RASPBERRY_PI_FIRMWARE_PROTOL_GUID \
  { 0x0ACA9535, 0x7AD0, 0x4286, { 0xB0, 0x2E, 0x87, 0xFA, 0x7E, 0x2A, 0x57, 0x11 } }

//
// Firmware crypto service (see https://github.com/raspberrypi/utils, directory
// rpifwcrypto): a mailbox API that performs a limited set of operations with
// the device private key held in OTP without handing the key itself out.
//
// Key id 1 is the device unique private key, i.e. the same key that
// rpi-otp-private-key provisions and that Linux exposes as
// /sys/bus/nvmem/devices/nvmem_priv0/nvmem. Flags are currently unused and
// must be 0.
//
#define RPI_FW_CRYPTO_DEVICE_KEY_ID      1
#define RPI_FW_CRYPTO_HMAC_MSG_MAX_SIZE  2048
#define RPI_FW_CRYPTO_HMAC_SIZE          32

//
// Key status bits (ARM_CRYPTO_KEY_STATUS_* in rpifwcrypto.h). The lock bits
// are volatile: they hold until the next reset, so they say what the rest of
// this power-on session may do with the key, and are set with
// SET_CRYPTO_KEY_STATUS.
//
#define RPI_FW_CRYPTO_KEY_STATUS_TYPE_DEVICE_PRIVATE_KEY  BIT0
#define RPI_FW_CRYPTO_KEY_STATUS_READ_LOCKED              BIT8
#define RPI_FW_CRYPTO_KEY_STATUS_GEN_LOCKED               BIT9
#define RPI_FW_CRYPTO_KEY_STATUS_SIGN_LOCKED              BIT10
#define RPI_FW_CRYPTO_KEY_STATUS_HMAC_LOCKED              BIT11
#define RPI_FW_CRYPTO_KEY_STATUS_USAGE_LOCKED             BIT12

//
// Firmware crypto error codes (RPI_FW_CRYPTO_STATUS in rpifwcrypto.h), as
// returned by GET_CRYPTO_LAST_ERROR. Only the ones this platform reports on
// are listed; anything else is passed through to the caller as-is.
//
#define RPI_FW_CRYPTO_SUCCESS            0
#define RPI_FW_CRYPTO_ERROR_UNKNOWN      1
#define RPI_FW_CRYPTO_KEY_NOT_FOUND      3
#define RPI_FW_CRYPTO_KEY_LOCKED         4
#define RPI_FW_CRYPTO_KEY_NOT_SET        6
#define RPI_FW_CRYPTO_KEY_INVALID        7
#define RPI_FW_CRYPTO_NOT_SUPPORTED      8
#define RPI_FW_CRYPTO_KEY_NOT_BLANK      10

typedef
EFI_STATUS
(EFIAPI *SET_POWER_STATE) (
  IN  UINT32    DeviceId,
  IN  BOOLEAN   PowerState,
  IN  BOOLEAN   Wait
  );

typedef
EFI_STATUS
(EFIAPI *GET_MAC_ADDRESS) (
  OUT UINT8     MacAddress[6]
  );

typedef
EFI_STATUS
(EFIAPI *GET_COMMAND_LINE) (
  IN  UINTN     BufferSize,
  OUT CHAR8     CommandLine[]
  );

typedef
EFI_STATUS
(EFIAPI *GET_CLOCK_STATE) (
  IN  UINT32    ClockId,
  OUT UINT32    *ClockState
  );

typedef
EFI_STATUS
(EFIAPI *SET_CLOCK_STATE) (
  IN  UINT32 ClockId,
  IN  UINT32 ClockState
  );

typedef
EFI_STATUS
(EFIAPI *GET_CLOCK_RATE) (
  IN  UINT32    ClockId,
  OUT UINT32    *ClockRate
  );

typedef
EFI_STATUS
(EFIAPI *SET_CLOCK_RATE) (
  IN  UINT32    ClockId,
  OUT UINT32    ClockRate,
  IN  BOOLEAN   SkipTurbo
  );

typedef
EFI_STATUS
(EFIAPI *GET_FB) (
  IN  UINT32 Width,
  IN  UINT32 Height,
  IN  UINT32 Depth,
  OUT EFI_PHYSICAL_ADDRESS *FbBase,
  OUT UINTN *FbSize,
  OUT UINTN *Pitch
  );

typedef
EFI_STATUS
(EFIAPI *GET_FB_SIZE) (
  OUT   UINT32 *Width,
  OUT   UINT32 *Height
  );

typedef
EFI_STATUS
(EFIAPI *FREE_FB) (
  VOID
  );

typedef
VOID
(EFIAPI *SET_LED) (
  BOOLEAN On
  );

typedef
EFI_STATUS
(EFIAPI *GET_SERIAL) (
  UINT64 *Serial
  );

typedef
EFI_STATUS
(EFIAPI *GET_MODEL) (
  UINT32 *Model
  );

typedef
EFI_STATUS
(EFIAPI *GET_MODEL_REVISION) (
  UINT32 *Revision
  );

typedef
CHAR8*
(EFIAPI *GET_MODEL_NAME) (
  INTN ModelId
  );

typedef
EFI_STATUS
(EFIAPI *GET_MODEL_FAMILY) (
  UINT32 *ModelFamily
  );

typedef
EFI_STATUS
(EFIAPI *GET_FIRMWARE_REVISION) (
  UINT32 *Revision
  );

typedef
EFI_STATUS
(EFIAPI *GET_MODEL_INSTALLED_MB) (
  UINT32 *InstalledMB
  );

typedef
CHAR8*
(EFIAPI *GET_MANUFACTURER_NAME) (
  INTN ManufacturerId
  );

typedef
CHAR8*
(EFIAPI *GET_CPU_NAME) (
  INTN CpuId
  );

typedef
EFI_STATUS
(EFIAPI *GET_ARM_MEM) (
  UINT32 *Base,
  UINT32 *Size
  );

typedef
EFI_STATUS
(EFIAPI *NOTIFY_XHCI_RESET) (
  UINTN BusNumber,
  UINTN DeviceNumber,
  UINTN FunctionNumber
  );

typedef
EFI_STATUS
(EFIAPI *GPIO_SET_CFG) (
  UINTN Gpio,
  UINTN Direction,
  UINTN State
  );

//
// Compute HMAC-SHA256 over Message, keyed with the OTP key KeyId, and return
// the RPI_FW_CRYPTO_HMAC_SIZE byte result in Hmac. MessageSize must be
// non-zero and at most RPI_FW_CRYPTO_HMAC_MSG_MAX_SIZE. The key never leaves
// the firmware, so unlike the raw OTP read this keeps working when config.txt
// sets lock_device_private_key=1.
//
// The key must already have been provisioned (rpi-otp-private-key, or
// rpi-fw-crypto genkey which generates it inside the firmware) and must be a
// valid ECDSA P-256 private key; the firmware rejects HMAC requests against a
// blank or malformed key. GET_CRYPTO_LAST_ERROR tells which it was.
//
typedef
EFI_STATUS
(EFIAPI *CRYPTO_HMAC_SHA256) (
  IN  UINT32       Flags,
  IN  UINT32       KeyId,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  OUT UINT8        *Hmac
  );

//
// Generate an ECDSA P-256 key pair in the OTP slot KeyId. The key material is
// created inside the firmware and never crosses the mailbox, but the write is
// a one-time, irreversible OTP burn: the slot must be blank (the firmware
// answers RPI_FW_CRYPTO_KEY_NOT_BLANK otherwise), and config.txt's
// lock_device_key_write=1, or GEN_LOCKED on the key, blocks it outright.
//
typedef
EFI_STATUS
(EFIAPI *CRYPTO_GEN_ECDSA_KEY) (
  IN  UINT32    Flags,
  IN  UINT32    KeyId
  );

//
// Read and set the volatile lock bits of an OTP key. Locks only ever go on,
// and only until the next reset; there is no way to lift one for the current
// session. Note that READ_LOCKED is only honoured by the older raw
// GET/SET USER OTP mailbox API from firmware 2026-01-09 onwards -- before
// that, only config.txt's lock_device_private_key=1 covers it.
//
typedef
EFI_STATUS
(EFIAPI *GET_CRYPTO_KEY_STATUS) (
  IN  UINT32    KeyId,
  OUT UINT32    *KeyStatus
  );

typedef
EFI_STATUS
(EFIAPI *SET_CRYPTO_KEY_STATUS) (
  IN  UINT32    KeyId,
  IN  UINT32    KeyStatus
  );

//
// Retrieve the firmware crypto service's last error code (one of the
// RPI_FW_CRYPTO_* values above). Purely diagnostic: it is only meaningful
// immediately after a failed crypto call.
//
typedef
EFI_STATUS
(EFIAPI *GET_CRYPTO_LAST_ERROR) (
  OUT UINT32    *Error
  );

typedef struct {
  SET_POWER_STATE        SetPowerState;
  GET_MAC_ADDRESS        GetMacAddress;
  GET_COMMAND_LINE       GetCommandLine;
  GET_CLOCK_RATE         GetClockRate;
  GET_CLOCK_RATE         GetMaxClockRate;
  GET_CLOCK_RATE         GetMinClockRate;
  SET_CLOCK_RATE         SetClockRate;
  GET_FB                 GetFB;
  FREE_FB                FreeFB;
  GET_FB_SIZE            GetFBSize;
  SET_LED                SetLed;
  GET_SERIAL             GetSerial;
  GET_MODEL              GetModel;
  GET_MODEL_REVISION     GetModelRevision;
  GET_MODEL_NAME         GetModelName;
  GET_MODEL_FAMILY       GetModelFamily;
  GET_FIRMWARE_REVISION  GetFirmwareRevision;
  GET_MANUFACTURER_NAME  GetManufacturerName;
  GET_CPU_NAME           GetCpuName;
  GET_ARM_MEM            GetArmMem;
  GET_MODEL_INSTALLED_MB GetModelInstalledMB;
  NOTIFY_XHCI_RESET      NotifyXhciReset;
  GET_CLOCK_STATE        GetClockState;
  SET_CLOCK_STATE        SetClockState;
  GPIO_SET_CFG           SetGpioConfig;
  CRYPTO_HMAC_SHA256     CryptoHmacSha256;
  CRYPTO_GEN_ECDSA_KEY   CryptoGenEcdsaKey;
  GET_CRYPTO_KEY_STATUS  GetCryptoKeyStatus;
  SET_CRYPTO_KEY_STATUS  SetCryptoKeyStatus;
  GET_CRYPTO_LAST_ERROR  GetCryptoLastError;
} RASPBERRY_PI_FIRMWARE_PROTOCOL;

extern EFI_GUID gRaspberryPiFirmwareProtocolGuid;

#endif /* __RASPBERRY_PI_FIRMWARE_PROTOCOL_H__ */
