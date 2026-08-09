/** @file
 *
 *  Serves the systemd-boot "LoaderBootSecret" EFI variable (see
 *  https://github.com/systemd/systemd/pull/41217) from a value derived, inside
 *  the VideoCore firmware, from the RPi4/CM4 device private key in OTP,
 *  instead of the platform's regular NV variable store.
 *
 *  This is necessary because RPi4's NV variable store is a region within
 *  RPI_EFI.fd itself. Signed boot sets config.txt's boot_ramdisk=1, so
 *  RPI_EFI.fd is carried inside the signed boot.img and executed from a
 *  ramdisk: there is no longer a file on the boot medium for
 *  VarBlockServiceDxe to rewrite in place, and NV variable writes are simply
 *  not persisted at all. A LoaderBootSecret left to the normal store would
 *  therefore be regenerated on every boot and never mean anything. Instead,
 *  the value is recomputed from the SoC's OTP on every boot and served
 *  directly out of RAM by wrapping gRT->GetVariable/SetVariable for just this
 *  single GUID+name pair; every other variable passes through untouched.
 *
 *  The secret is *derived*, not stored:
 *
 *    LoaderBootSecret = HMAC-SHA256 (device private key,
 *                                    "LoaderBootSecret-v1 <serial>")
 *
 *  where <serial> is the 64-bit board serial (mailbox tag 0x00010004, the same
 *  value Linux reports as "Serial" in /proc/cpuinfo) formatted as 16 lowercase
 *  hex digits, and the message is plain ASCII with no NUL terminator. The
 *  label keeps this secret distinct from anything else derived from the same
 *  key, e.g. the HMAC(serial + eMMC CID) LUKS passphrase that Raspberry Pi's
 *  rpifwcrypto README suggests.
 *
 *  The HMAC is computed by the firmware crypto service (mailbox tag
 *  0x00030092, see https://github.com/raspberrypi/utils in rpifwcrypto), so
 *  the key itself is never read into the ARM's address space. Two practical
 *  consequences:
 *
 *  1. This works with config.txt's lock_device_private_key=1, which blocks the
 *     raw OTP read API for the rest of the power-on session but deliberately
 *     leaves sign/hmac/pubkey working. Raspberry Pi recommend setting it
 *     whenever secure boot is enabled, so a design that needs the raw key
 *     would be at odds with the recommended configuration.
 *  2. The key gets provisioned without being exposed either. A board that was
 *     provisioned earlier, with rpi-fw-crypto genkey or rpi-otp-private-key,
 *     is used as-is; on a board whose slot is still blank the firmware answers
 *     KEY_NOT_SET, and the driver asks it to generate an ECDSA P-256 key in
 *     place (mailbox tag 0x00030095, what "rpi-fw-crypto genkey --key-id 1
 *     --alg ec" does) and retries the HMAC once. Again the key material is
 *     created inside the VideoCore and never crosses the mailbox.
 *
 *     Note what that means: enabling this feature on a board with a blank slot
 *     permanently consumes the board's device private key on the first boot
 *     that asks for the secret. It is a one-time, irreversible OTP burn, so do
 *     not enable it on a board whose key is meant for something else. It is
 *     attempted at most once per boot, only when the firmware has just said
 *     the slot is blank, and it needs config.txt to leave lock_device_key_write
 *     unset, since that blocks key generation for the whole session.
 *
 *     A slot holding something that is not a valid ECDSA P-256 key -- raw
 *     random bytes written with rpi-otp-private-key, say -- cannot be fixed
 *     here: the firmware rejects the HMAC, and generation is refused because
 *     the slot is not blank.
 *
 *  The firmware will otherwise HMAC anything for anyone, so an OS-side root
 *  process could simply ask it for the same value. To stop that, the driver
 *  locks the key at ExitBootServices(), just before control reaches the OS:
 *  HMAC_LOCKED so the derivation cannot be repeated, and READ_LOCKED so the
 *  raw key cannot be read out and used to compute it elsewhere -- either lock
 *  without the other is worth nothing. Signing, key generation and key usage
 *  are locked along with them, since nothing else here needs the key either
 *  and the last two also cover writes to OTP. The locks are volatile: they
 *  hold until the next reset and cannot be lifted for the current session.
 *
 *  The consequence is that the device private key is unusable by the OS for
 *  anything else, on every boot that goes through this firmware with the
 *  feature enabled. That is the intended trade -- here the key exists for the
 *  boot secret -- but it does mean an OS-side user of the same key (Raspberry
 *  Pi Connect, say, or an initramfs deriving a LUKS passphrase) cannot coexist
 *  with turning this on.
 *
 *  Locking is best effort: it happens where there is no longer anyone to
 *  report to, so a failure is logged loudly but does not stop the boot --
 *  refusing to boot a system whose secret has already been handed to the
 *  loader would help no one. The status is read back and compared, so the log
 *  says whether the locks really took rather than assuming they did.
 *
 *  What is left, then: the secret exists nowhere at rest -- not in the
 *  variable store, not on the boot medium -- and cannot be recomputed from the
 *  running OS. What it still is not: protection against someone who has the
 *  board, and who can boot something that never applies the locks (stock
 *  Raspberry Pi OS, no UEFI in the path) and ask the firmware for the HMAC.
 *  Only signed boot plus Secure Boot closes that, by making this firmware the
 *  one thing that runs -- which is why the driver refuses to serve the
 *  variable at all unless both are in force; see the gates below.
 *  LoaderBootSecret is a fallback for TPM-backed secrets, not an equivalent of
 *  one.
 *
 *  That last gap is also the recovery path: given the board, the secret can be
 *  recomputed by hand from a boot that does not apply the locks, so a resource
 *  protected with it is not lost if the ESP is reinstalled.
 *
 *    SERIAL=$(awk '/^Serial/ { print $3 }' /proc/cpuinfo)
 *    printf 'LoaderBootSecret-v1 %s' "$SERIAL" > message.bin
 *    rpi-fw-crypto hmac --in message.bin --key-id 1 --out secret.bin
 *
 *  (On a board whose firmware reports a zero serial, GetSerial() substitutes
 *  a MAC-derived value and /proc/cpuinfo does not match. RPi4 always reports
 *  a serial.)
 *
 *  This is opt-in, disabled by default: the UINT8
 *  EnableOtpDerivedLoaderBootSecret variable (GUID gConfigDxeFormSetGuid, the
 *  same namespace as RPi4's other settings like RamLimitTo3GB) must be set to
 *  a non-zero value. Under signed boot that means baking it into the image
 *  with virt-fw-vars before signing, since nothing written at runtime (by the
 *  UEFI Shell's 'setvar', say) survives a reset.
 *
 *  Opting in is not enough on its own, though. Handing a boot secret to the
 *  loader only means something if this firmware is the one thing that can run
 *  on the board and the loader is one it has verified, so the driver also
 *  requires:
 *
 *  1. SECURE_BOOT_ENABLE=TRUE at build time. Without it there is no image
 *     verification in the build to authenticate the loader with, so the driver
 *     is not built into the image at all (see RPi4.dsc and RPi4.fdf).
 *  2. RPi signed boot. The VideoCore bootloader reports what it enforced in
 *     the devicetree property /chosen/bootloader/signed (the same one Linux
 *     exposes as /proc/device-tree/chosen/bootloader/signed), and SIGNED_BOOT
 *     must be configured there, i.e. this boot came out of a boot.img whose
 *     signature the bootloader checked.
 *
 *     The two OTP fuses that make that permanent -- the customer public key
 *     hash, and the revoked ROM development key -- are warned about but not
 *     required. Both are irreversible, and gating on either would mean the
 *     feature could not be tried at all without first spending them on a board
 *     that may only be a test board. They are what finally closes the door,
 *     though: until they are burnt, the bootloader configuration can be
 *     replaced and the ROM will still start an unsigned bootloader, either of
 *     which can ask the firmware for the same HMAC. So they are the last step
 *     for a board that is meant to keep this secret, taken once the rest is
 *     known to work.
 *  3. UEFI Secure Boot active in this boot, i.e. SecureBoot == 1. Signed boot
 *     only gets as far as this firmware; Secure Boot is what keeps the secret
 *     from being handed to an unverified loader.
 *
 *  Fail any of these -- or leave the variable unset -- and this driver does
 *  nothing at all: no mailbox traffic, no key generation, no gRT hook, and the
 *  variable simply does not exist.
 *
 *  When the derivation fails (key not provisioned, locked, firmware too old to
 *  implement the crypto tags), ShimGetVariable() deliberately reports
 *  EFI_DEVICE_ERROR rather than EFI_NOT_FOUND. sd-stub only creates and stores
 *  a secret of its own when the read returns EFI_NOT_FOUND (see
 *  acquire_efivar_secret() in systemd's boot-secret.c), and such a write would
 *  land in the ordinary NV store -- which on a board not using signed boot
 *  means a plaintext copy of the boot secret on the card. Failing with any
 *  other error keeps sd-stub from doing that: it just boots with no boot
 *  secret at all.
 *
 *  Copyright (c) 2026, Valtteri R
 *
 *  SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 **/

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Protocol/RpiFirmware.h>

//
// systemd's LOADER_GUID (src/boot/efi-efivars.h)
//
STATIC CONST EFI_GUID  mLoaderGuid = {
  0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f }
};

#define LOADER_BOOT_SECRET_NAME  L"LoaderBootSecret"
#define BOOT_SECRET_SIZE         RPI_FW_CRYPTO_HMAC_SIZE
#define ENABLE_VARIABLE_NAME     L"EnableOtpDerivedLoaderBootSecret"

//
// Domain separation label for the HMAC message; see the note at the top of
// this file for the exact byte string. Bump the version suffix if the message
// composition ever changes, since that changes every board's secret.
//
#define BOOT_SECRET_LABEL        "LoaderBootSecret-v1 "
#define SERIAL_HEX_DIGITS        16

//
// What the VideoCore bootloader enforced on the way here, as it reports it in
// the devicetree: /chosen/bootloader/signed, a big-endian UINT32 of flags.
// This is the same property and the same bits that Raspberry Pi's fastbootd
// reads back as the signed-eeprom / signed-devkey / signed-otp variables (see
// GetSignedEeprom(), GetSignedDevkey() and GetSignedOtp() in
// https://github.com/raspberrypi/rpi-fastbootd, fastboot/device/variables.cpp).
//
#define SIGNED_BOOT_NODE_PATH         "/chosen/bootloader"
#define SIGNED_BOOT_PROPERTY_NAME     "signed"
#define SIGNED_BOOT_EEPROM_CONFIG     BIT0  // SIGNED_BOOT=1 in the EEPROM config
#define SIGNED_BOOT_DEVKEY_REVOKED    BIT2  // ROM development key revoked in OTP
#define SIGNED_BOOT_KEY_HASH_IN_OTP   BIT3  // customer public key hash burnt into OTP

//
// Only the configured bit is required: this boot has to have come through a
// signature check, but the two OTP fuses that would make that permanent are
// deliberately left out and merely warned about, since both are irreversible
// and requiring either would mean spending them on a board before the feature
// has ever been seen to work. Burning them is the owner's last step, not this
// driver's precondition.
//
#define SIGNED_BOOT_REQUIRED  SIGNED_BOOT_EEPROM_CONFIG

//
// What that step consists of, and so what this driver is still trusting the
// owner to get to: until both are set, the bootloader configuration can be
// replaced, and the ROM will start an unsigned bootloader that never applies
// the key locks.
//
#define SIGNED_BOOT_FUSED     (SIGNED_BOOT_DEVKEY_REVOKED | \
                               SIGNED_BOOT_KEY_HASH_IN_OTP)

//
// Applied to the device private key at ExitBootServices(). Everything the
// firmware can lock: once the secret has been derived, nothing later in this
// session has any business with the key at all, and two of these bits (GEN,
// USAGE) also cover writes to OTP.
//
#define BOOT_SECRET_KEY_LOCKS    (RPI_FW_CRYPTO_KEY_STATUS_READ_LOCKED  | \
                                  RPI_FW_CRYPTO_KEY_STATUS_GEN_LOCKED   | \
                                  RPI_FW_CRYPTO_KEY_STATUS_SIGN_LOCKED  | \
                                  RPI_FW_CRYPTO_KEY_STATUS_HMAC_LOCKED  | \
                                  RPI_FW_CRYPTO_KEY_STATUS_USAGE_LOCKED)

//
// The subset that actually protects the secret, and so the only part worth
// failing over: fine-grained locking is recent, and an older firmware that
// ignores the rest is still doing the job that matters here.
//
#define BOOT_SECRET_KEY_LOCKS_REQUIRED  (RPI_FW_CRYPTO_KEY_STATUS_READ_LOCKED | \
                                         RPI_FW_CRYPTO_KEY_STATUS_HMAC_LOCKED)

STATIC UINT8                           mBootSecret[BOOT_SECRET_SIZE];
STATIC BOOLEAN                         mBootSecretAvailable = FALSE;
STATIC BOOLEAN                         mHooked = FALSE;
STATIC BOOLEAN                         mLockKeyAtExitBootServices = FALSE;
STATIC BOOLEAN                         mKeyGenerationTried = FALSE;
STATIC EFI_GET_VARIABLE                mOriginalGetVariable;
STATIC EFI_SET_VARIABLE                mOriginalSetVariable;
STATIC EFI_EVENT                       mExitBootServicesEvent;
STATIC RASPBERRY_PI_FIRMWARE_PROTOCOL  *mFirmware;

STATIC CONST CHAR8  mHexChars[] = "0123456789abcdef";

STATIC
BOOLEAN
IsLoaderBootSecret (
  IN CONST CHAR16    *VariableName,
  IN CONST EFI_GUID  *VendorGuid
  )
{
  return (VariableName != NULL) && (VendorGuid != NULL) &&
         CompareGuid (VendorGuid, &mLoaderGuid) &&
         (StrCmp (VariableName, LOADER_BOOT_SECRET_NAME) == 0);
}

/**
  The firmware crypto service reports why it refused the last request through a
  tag of its own, so a failed call has to be followed by a second one to learn
  anything. Returns RPI_FW_CRYPTO_ERROR_UNKNOWN if even that does not answer.
**/
STATIC
UINT32
GetLastCryptoError (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT32      Error;

  Status = mFirmware->GetCryptoLastError (&Error);
  if (EFI_ERROR (Status)) {
    return RPI_FW_CRYPTO_ERROR_UNKNOWN;
  }

  return Error;
}

/**
  Log why the firmware refused a crypto request, since the distinction decides
  what the owner has to do about it.
**/
STATIC
VOID
ReportCryptoError (
  IN UINT32  Error
  )
{
  switch (Error) {
    case RPI_FW_CRYPTO_KEY_NOT_SET:
    case RPI_FW_CRYPTO_KEY_INVALID:
      DEBUG ((DEBUG_ERROR, "%a: device private key (id %u) is blank or not a valid ECDSA P-256 key\n",
        __func__, RPI_FW_CRYPTO_DEVICE_KEY_ID));
      break;
    case RPI_FW_CRYPTO_KEY_LOCKED:
      DEBUG ((DEBUG_ERROR, "%a: device private key (id %u) is locked for this operation;"
        " config.txt may be setting lock_device_key_write=1\n",
        __func__, RPI_FW_CRYPTO_DEVICE_KEY_ID));
      break;
    case RPI_FW_CRYPTO_NOT_SUPPORTED:
    case RPI_FW_CRYPTO_KEY_NOT_FOUND:
      DEBUG ((DEBUG_ERROR, "%a: the firmware crypto service does not offer key id %u;"
        " a firmware update may be required\n", __func__, RPI_FW_CRYPTO_DEVICE_KEY_ID));
      break;
    default:
      DEBUG ((DEBUG_ERROR, "%a: firmware crypto error %u\n", __func__, Error));
      break;
  }
}

/**
  First boot on a board whose device private key slot is still blank: have the
  firmware generate an ECDSA P-256 key in place. The key material is created
  inside the VideoCore and never crosses the mailbox, so nothing here ever sees
  it -- but the write is a one-time, irreversible OTP burn, so it is attempted
  at most once per boot and only when the firmware itself has just said the
  slot is blank.

  @retval EFI_SUCCESS  The slot now holds a key.
  @retval other        Generation failed; the slot is untouched.
**/
STATIC
EFI_STATUS
GenerateDeviceKey (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mKeyGenerationTried) {
    return EFI_ALREADY_STARTED;
  }

  mKeyGenerationTried = TRUE;

  DEBUG ((DEBUG_WARN, "%a: device private key (id %u) is blank, asking the firmware to generate one"
    " (one-time, irreversible)\n", __func__, RPI_FW_CRYPTO_DEVICE_KEY_ID));

  Status = mFirmware->CryptoGenEcdsaKey (0, RPI_FW_CRYPTO_DEVICE_KEY_ID);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to generate a device private key: %r\n", __func__, Status));
    ReportCryptoError (GetLastCryptoError ());
    return Status;
  }

  DEBUG ((DEBUG_INFO, "%a: generated a device private key in OTP slot %u\n",
    __func__, RPI_FW_CRYPTO_DEVICE_KEY_ID));

  return EFI_SUCCESS;
}

/**
  Ask the firmware to HMAC Message with the device private key, straight into
  mBootSecret.
**/
STATIC
EFI_STATUS
HmacIntoBootSecret (
  IN CONST CHAR8  *Message,
  IN UINTN        MessageSize
  )
{
  return mFirmware->CryptoHmacSha256 (
                      0,
                      RPI_FW_CRYPTO_DEVICE_KEY_ID,
                      (CONST UINT8 *)Message,
                      MessageSize,
                      mBootSecret
                      );
}

/**
  Derive the boot secret and cache it for the rest of the boot.

  @retval EFI_SUCCESS  mBootSecret holds the derived value.
  @retval other        Nothing usable could be derived; mBootSecret is
                       untouched and mBootSecretAvailable stays FALSE.
**/
STATIC
EFI_STATUS
EnsureBootSecret (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT64      Serial;
  CHAR8       Message[sizeof (BOOT_SECRET_LABEL) - 1 + SERIAL_HEX_DIGITS];
  UINTN       Index;

  if (mBootSecretAvailable) {
    return EFI_SUCCESS;
  }

  Status = mFirmware->GetSerial (&Serial);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to read the board serial: %r\n", __func__, Status));
    return Status;
  }

  CopyMem (Message, BOOT_SECRET_LABEL, sizeof (BOOT_SECRET_LABEL) - 1);
  for (Index = 0; Index < SERIAL_HEX_DIGITS; Index++) {
    Message[sizeof (BOOT_SECRET_LABEL) - 1 + Index] =
      mHexChars[(Serial >> (4 * (SERIAL_HEX_DIGITS - 1 - Index))) & 0xF];
  }

  Status = HmacIntoBootSecret (Message, sizeof (Message));
  if (EFI_ERROR (Status)) {
    //
    // A blank key slot is the first-boot case rather than a real failure:
    // provision it and try the derivation once more. Any other reason is not
    // something that can be fixed from here.
    //
    if (GetLastCryptoError () == RPI_FW_CRYPTO_KEY_NOT_SET) {
      Status = GenerateDeviceKey ();
      if (!EFI_ERROR (Status)) {
        Status = HmacIntoBootSecret (Message, sizeof (Message));
      }
    }
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to derive the boot secret: %r\n", __func__, Status));
    ReportCryptoError (GetLastCryptoError ());
    ZeroMem (mBootSecret, sizeof (mBootSecret));
    return Status;
  }

  mBootSecretAvailable = TRUE;
  DEBUG ((DEBUG_INFO, "%a: derived %s from the device private key\n",
    __func__, LOADER_BOOT_SECRET_NAME));

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ShimGetVariable (
  IN     CHAR16    *VariableName,
  IN     EFI_GUID  *VendorGuid,
  OUT    UINT32    *Attributes OPTIONAL,
  IN OUT UINTN     *DataSize,
  OUT    VOID      *Data OPTIONAL
  )
{
  EFI_STATUS  Status;

  if (IsLoaderBootSecret (VariableName, VendorGuid)) {
    if (DataSize == NULL) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // Answer the size query without touching OTP: the size is fixed, and
    // callers ask for it before they have a buffer to receive the value.
    //
    if (*DataSize < sizeof (mBootSecret)) {
      *DataSize = sizeof (mBootSecret);
      return EFI_BUFFER_TOO_SMALL;
    }

    if (Data == NULL) {
      return EFI_INVALID_PARAMETER;
    }

    Status = EnsureBootSecret ();
    if (EFI_ERROR (Status)) {
      //
      // Anything but EFI_NOT_FOUND, so that sd-stub does not fall back to
      // creating a secret of its own in the ordinary variable store.
      //
      return EFI_DEVICE_ERROR;
    }

    CopyMem (Data, mBootSecret, sizeof (mBootSecret));
    *DataSize = sizeof (mBootSecret);

    if (Attributes != NULL) {
      //
      // Non-volatile + boot-service-access only: no EFI_VARIABLE_RUNTIME_ACCESS,
      // so this becomes inaccessible to the OS once ExitBootServices() is called.
      // sd-stub rejects the variable if the attributes say anything else.
      //
      *Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;
    }

    return EFI_SUCCESS;
  }

  return mOriginalGetVariable (VariableName, VendorGuid, Attributes, DataSize, Data);
}

STATIC
EFI_STATUS
EFIAPI
ShimSetVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID      *Data
  )
{
  if (IsLoaderBootSecret (VariableName, VendorGuid)) {
    //
    // The value is a function of the board, not something anyone gets to
    // choose or delete: there is nowhere to put a caller's value, and letting
    // the write through to the real store would leave a second, contradictory
    // copy of the variable behind our back.
    //
    DEBUG ((DEBUG_WARN, "%a: %s is derived from OTP and cannot be written\n",
      __func__, LOADER_BOOT_SECRET_NAME));
    return EFI_WRITE_PROTECTED;
  }

  return mOriginalSetVariable (VariableName, VendorGuid, Attributes, DataSize, Data);
}

/**
  Take the device private key away from the OS for the rest of this power-on
  session, so that the boot secret cannot be recomputed once the loader has
  handed it on. Best effort by nature -- there is nobody left to report to --
  but the outcome is verified and logged either way.
**/
STATIC
VOID
LockDeviceKey (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT32      KeyStatus;

  Status = mFirmware->SetCryptoKeyStatus (RPI_FW_CRYPTO_DEVICE_KEY_ID, BOOT_SECRET_KEY_LOCKS);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to lock the device private key: %r; the OS can recompute %s\n",
      __func__, Status, LOADER_BOOT_SECRET_NAME));
    ReportCryptoError (GetLastCryptoError ());
    return;
  }

  Status = mFirmware->GetCryptoKeyStatus (RPI_FW_CRYPTO_DEVICE_KEY_ID, &KeyStatus);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: cannot confirm the device private key locks took: %r\n", __func__, Status));
    return;
  }

  if ((KeyStatus & BOOT_SECRET_KEY_LOCKS_REQUIRED) != BOOT_SECRET_KEY_LOCKS_REQUIRED) {
    DEBUG ((DEBUG_ERROR, "%a: device private key locks did not take (status 0x%x);"
      " the OS can recompute %s\n", __func__, KeyStatus, LOADER_BOOT_SECRET_NAME));
    return;
  }

  DEBUG ((DEBUG_INFO, "%a: device private key locked until the next reset (status 0x%x)\n",
    __func__, KeyStatus));
}

STATIC
VOID
EFIAPI
UnhookOnExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  BOOLEAN  Restored;

  //
  // Only ever from the real ExitBootServices() notification: the init path
  // below also calls this function to unwind a half-installed hook, and that
  // must not leave the key locked for a boot that never used it.
  //
  if (mLockKeyAtExitBootServices) {
    mLockKeyAtExitBootServices = FALSE;
    LockDeviceKey ();
  }

  //
  // Our shim functions live in boot-services memory that the OS is free to
  // reclaim once ExitBootServices() returns. Restore the real GetVariable/
  // SetVariable before that happens: any runtime GetVariable call for
  // LoaderBootSecret then simply falls through to the (empty) real store and
  // correctly returns EFI_NOT_FOUND, which is the desired "invisible to the
  // OS" behavior anyway.
  //
  if (!mHooked) {
    return;
  }

  //
  // Unwind only our own hook. If something else hooked these after us, the
  // pointers we saved are stale: writing them back would drop the other
  // component's hook, and if that component unhooks after us it would restore
  // *ours* -- a pointer into memory the OS is about to reclaim, called at OS
  // runtime. Leaving the chain alone is the safe answer in that case; our
  // secret is still wiped below either way.
  //
  Restored = FALSE;

  if (gRT->GetVariable == ShimGetVariable) {
    gRT->GetVariable = mOriginalGetVariable;
    Restored         = TRUE;
  } else {
    DEBUG ((DEBUG_WARN, "%a: GetVariable was re-hooked by another component, leaving it alone\n", __func__));
  }

  if (gRT->SetVariable == ShimSetVariable) {
    gRT->SetVariable = mOriginalSetVariable;
    Restored         = TRUE;
  } else {
    DEBUG ((DEBUG_WARN, "%a: SetVariable was re-hooked by another component, leaving it alone\n", __func__));
  }

  if (Restored) {
    gRT->Hdr.CRC32 = 0;
    gRT->Hdr.CRC32 = CalculateCrc32 ((VOID *)gRT, gRT->Hdr.HeaderSize);
  }

  mHooked              = FALSE;
  mBootSecretAvailable = FALSE;
  ZeroMem (mBootSecret, sizeof (mBootSecret));
}

/**
  Whether the VideoCore bootloader verified what it loaded, i.e. SIGNED_BOOT in
  the EEPROM configuration. Whether OTP makes that permanent is only logged;
  see SIGNED_BOOT_REQUIRED.

  Read from the devicetree the firmware left at PcdFdtBaseAddress, which is the
  firmware's own copy -- the one FdtDxe reads too -- and not something a later
  component composed, so it is still there whether or not the devicetree is
  handed on to the OS.

  @retval TRUE   Signed boot is in force on this board.
  @retval FALSE  It is not, or the firmware did not say.
**/
STATIC
BOOLEAN
IsSignedBootEnforced (
  VOID
  )
{
  CONST VOID  *Fdt;
  CONST VOID  *Property;
  INT32       Node;
  INT32       PropertySize;
  UINT32      SignedState;

  Fdt = (CONST VOID *)(UINTN)FixedPcdGet32 (PcdFdtBaseAddress);
  if (FdtCheckHeader (Fdt) != 0) {
    DEBUG ((DEBUG_WARN, "%a: no devicetree from the VideoCore firmware;"
      " cannot tell whether signed boot is enforced\n", __func__));
    return FALSE;
  }

  Node = FdtPathOffset (Fdt, SIGNED_BOOT_NODE_PATH);
  if (Node < 0) {
    DEBUG ((DEBUG_WARN, "%a: no %a node in the devicetree;"
      " the firmware may be too old to report signed boot\n",
      __func__, SIGNED_BOOT_NODE_PATH));
    return FALSE;
  }

  Property = FdtGetProp (Fdt, Node, SIGNED_BOOT_PROPERTY_NAME, &PropertySize);
  if ((Property == NULL) || (PropertySize != sizeof (SignedState))) {
    DEBUG ((DEBUG_WARN, "%a: no usable %a/%a property in the devicetree\n",
      __func__, SIGNED_BOOT_NODE_PATH, SIGNED_BOOT_PROPERTY_NAME));
    return FALSE;
  }

  //
  // Devicetree property data is big-endian and only aligned to 4 bytes within
  // the blob, so copy it out rather than dereferencing it in place.
  //
  CopyMem (&SignedState, Property, sizeof (SignedState));
  SignedState = Fdt32ToCpu (SignedState);

  if ((SignedState & SIGNED_BOOT_REQUIRED) != SIGNED_BOOT_REQUIRED) {
    DEBUG ((DEBUG_WARN, "%a: signed boot is not in force (%a/%a = 0x%x, need 0x%x)\n",
      __func__, SIGNED_BOOT_NODE_PATH, SIGNED_BOOT_PROPERTY_NAME,
      SignedState, SIGNED_BOOT_REQUIRED));
    return FALSE;
  }

  if ((SignedState & SIGNED_BOOT_FUSED) != SIGNED_BOOT_FUSED) {
    DEBUG ((DEBUG_WARN, "%a: signed boot is not fused in OTP (%a/%a = 0x%x, fused 0x%x):"
      " unsigned code can still be started on this board and ask the firmware"
      " for %s\n", __func__, SIGNED_BOOT_NODE_PATH, SIGNED_BOOT_PROPERTY_NAME,
      SignedState, SIGNED_BOOT_FUSED, LOADER_BOOT_SECRET_NAME));
  }

  return TRUE;
}

/**
  Whether UEFI Secure Boot is in force for this boot. SecureBoot is set to 1
  only in User Mode with Secure Boot enabled, so it answers both questions at
  once; a platform in Setup Mode reports 0.

  @retval TRUE   Images are being verified.
  @retval FALSE  They are not, or the variable could not be read.
**/
STATIC
BOOLEAN
IsSecureBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT8       SecureBoot;
  UINTN       Size;

  SecureBoot = SECURE_BOOT_MODE_DISABLE;
  Size       = sizeof (SecureBoot);

  Status = gRT->GetVariable (EFI_SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid,
                             NULL, &Size, &SecureBoot);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "%a: cannot read %s: %r\n",
      __func__, EFI_SECURE_BOOT_MODE_NAME, Status));
    return FALSE;
  }

  if (SecureBoot != SECURE_BOOT_MODE_ENABLE) {
    DEBUG ((DEBUG_WARN, "%a: Secure Boot is not enabled (%s = %u)\n",
      __func__, EFI_SECURE_BOOT_MODE_NAME, SecureBoot));
    return FALSE;
  }

  return TRUE;
}

EFI_STATUS
EFIAPI
LoaderBootSecretDxeInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  UINT8       Enabled;
  UINTN       Size;

  Enabled = 0;
  Size    = sizeof (Enabled);
  Status  = gRT->GetVariable (ENABLE_VARIABLE_NAME, &gConfigDxeFormSetGuid, NULL, &Size, &Enabled);
  if (EFI_ERROR (Status) || (Enabled == 0)) {
    DEBUG ((DEBUG_INFO, "%a: %s not set, feature disabled (default)\n", __func__, ENABLE_VARIABLE_NAME));
    return EFI_SUCCESS;
  }

  //
  // The secret is only worth deriving on a board where this firmware is the
  // one thing that can run and it only hands the secret to a loader it has
  // verified. Without both, an OS that never applies the key locks can ask the
  // firmware for the same HMAC, so there is nothing to protect here -- and, as
  // this runs before any OTP is touched, nothing has been spent finding out.
  //
  if (!IsSignedBootEnforced () || !IsSecureBootEnabled ()) {
    DEBUG ((DEBUG_WARN, "%a: %s is set, but this boot is not covered by signed boot"
      " and Secure Boot; feature disabled\n", __func__, ENABLE_VARIABLE_NAME));
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (&gRaspberryPiFirmwareProtocolGuid, NULL, (VOID **)&mFirmware);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: RaspberryPiFirmwareProtocol not available: %r\n", __func__, Status));
    return EFI_SUCCESS;
  }

  //
  // The secret is derived lazily, on the first read that actually wants the
  // value: nothing else in the boot needs it, and there is no reason to keep a
  // copy in memory on a boot where no one asks.
  //
  mOriginalGetVariable = gRT->GetVariable;
  mOriginalSetVariable = gRT->SetVariable;
  gRT->GetVariable     = ShimGetVariable;
  gRT->SetVariable     = ShimSetVariable;
  mHooked              = TRUE;

  gRT->Hdr.CRC32 = 0;
  gRT->Hdr.CRC32 = CalculateCrc32 ((VOID *)gRT, gRT->Hdr.HeaderSize);

  //
  // The event is deliberately never closed: this is a DXE driver in the
  // firmware volume that is never unloaded, so it must stay armed for the
  // lifetime of the boot, and closing it from inside its own notification at
  // ExitBootServices() time would mean freeing pool right when the memory map
  // is being finalized.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  UnhookOnExitBootServices,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &mExitBootServicesEvent
                  );
  if (EFI_ERROR (Status)) {
    //
    // We must not leave the hook in place with no way to unwind it: fail
    // safe by unhooking right away and giving up on the derived variable for
    // this boot rather than risking a dangling pointer at OS runtime.
    //
    DEBUG ((DEBUG_ERROR, "%a: failed to register ExitBootServices notification: %r\n", __func__, Status));
    UnhookOnExitBootServices (NULL, NULL);
    return EFI_SUCCESS;
  }

  mLockKeyAtExitBootServices = TRUE;

  DEBUG ((DEBUG_INFO, "%a: %s now derived from the device private key in OTP\n",
    __func__, LOADER_BOOT_SECRET_NAME));

  return EFI_SUCCESS;
}
