//! macOS biometric key storage: a keychain item behind Touch ID.
//!
//! `docs/SECURITY.md` prefers `kSecAccessControlBiometryCurrentSet` over
//! `LAContext.evaluatePolicy` in front of a plain keychain read, and that
//! preference is the whole design:
//!
//! > Prefer `BiometryCurrentSet`: enrolling a new fingerprint invalidates the
//! > item.
//!
//! With `evaluatePolicy` the app asks "was that a valid finger?" and then reads
//! an unprotected item — two separable steps, and a local attacker who patches
//! the binary skips the first. With `BiometryCurrentSet` the item is *encrypted
//! by the Secure Enclave against the current enrolment set*. There is no
//! decision to patch: without a matching biometric the bytes do not come back,
//! and if the enrolment set changes the item is discarded by the OS.
//!
//! That last property is precisely the Phase 3 exit criterion: "Adding a
//! fingerprint in System Settings invalidates the stored key and forces the
//! password."
//!
//! # Signing
//!
//! Keychain access with an access-control policy requires a signed app with the
//! `keychain-access-groups` entitlement. `KICKOFF.md` flags this, and it is why
//! `docs/PHASE3-NOTES.md` records what has and has not been verified.

#![allow(unsafe_code)]

use std::ptr;

use core_foundation::base::{CFType, CFTypeRef, OSStatus, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFErrorRef;
use core_foundation::string::{CFString, CFStringRef};
use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
use zeroize::Zeroizing;

use crate::biometrics::{BiometricAvailability, BiometricFailure, BiometricProvider, BiometryKind};
use crate::error::{PlatformError, Result};

/// Keychain service name. Shared by every vault on the machine; the account
/// field distinguishes them.
const SERVICE: &str = "dev.vaulty.app";

// OSStatus values from <Security/SecBase.h>.
const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
const ERR_SEC_USER_CANCELED: OSStatus = -128;
const ERR_SEC_AUTH_FAILED: OSStatus = -25293;
/// The item's access control could not be satisfied — including because the
/// biometric enrolment set changed since it was written.
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;

/// `kSecAccessControlBiometryCurrentSet` — bit 3 of SecAccessControlCreateFlags.
///
/// Declared numerically because the symbol is not exported as a linkable
/// constant; the value is stable API from <Security/SecAccessControl.h>.
const BIOMETRY_CURRENT_SET: u32 = 1 << 3;

type SecAccessControlRef = CFTypeRef;
type CFAllocatorRef = *const std::ffi::c_void;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecUseOperationPrompt: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;

    fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: u32,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;

    fn SecItemAdd(attributes: *const std::ffi::c_void, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemCopyMatching(query: *const std::ffi::c_void, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemDelete(query: *const std::ffi::c_void) -> OSStatus;
}

/// Borrow a framework-owned CFString constant.
///
/// Safety: these are +0 globals that live for the process; `wrap_under_get_rule`
/// retains, so the wrapper owns its own reference.
unsafe fn constant(s: CFStringRef) -> CFString {
    CFString::wrap_under_get_rule(s)
}

unsafe fn constant_type(s: CFStringRef) -> CFType {
    CFType::wrap_under_get_rule(s as CFTypeRef)
}

#[derive(Debug, Default)]
pub struct KeychainProvider;

impl KeychainProvider {
    pub fn new() -> Self {
        Self
    }

    /// Build the access-control object the item is written with.
    ///
    /// `WhenUnlockedThisDeviceOnly` keeps it off backups and off other
    /// machines; `BiometryCurrentSet` binds it to the enrolment set in force
    /// right now.
    fn access_control() -> Result<CFType> {
        let mut error: CFErrorRef = ptr::null_mut();
        // Safety: passing a framework constant as the protection class and a
        // documented flag value; the out-param is checked before use.
        let ac = unsafe {
            SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                BIOMETRY_CURRENT_SET,
                &mut error,
            )
        };

        if ac.is_null() {
            // The CFError is leaked rather than inspected: its contents are not
            // actionable here and could carry device detail we have no use for.
            return Err(PlatformError::Os(
                "could not create keychain access control",
            ));
        }

        // Safety: SecAccessControlCreateWithFlags returns +1; take ownership.
        Ok(unsafe { CFType::wrap_under_create_rule(ac) })
    }

    fn base_query(account: &str) -> Vec<(CFString, CFType)> {
        // Safety: all constants are framework-owned globals.
        unsafe {
            vec![
                (constant(kSecClass), constant_type(kSecClassGenericPassword)),
                (
                    constant(kSecAttrService),
                    CFString::new(SERVICE).as_CFType(),
                ),
                (
                    constant(kSecAttrAccount),
                    CFString::new(account).as_CFType(),
                ),
            ]
        }
    }

    fn delete_raw(account: &str) -> OSStatus {
        let query = CFDictionary::from_CFType_pairs(&Self::base_query(account));
        // Safety: `query` outlives the call.
        unsafe { SecItemDelete(query.as_CFTypeRef() as *const _) }
    }
}

impl BiometricProvider for KeychainProvider {
    fn availability(&self) -> BiometricAvailability {
        let context = unsafe { LAContext::new() };

        // `canEvaluatePolicy` does not prompt; it reports whether a prompt
        // could succeed.
        let can = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };

        let kind = match unsafe { context.biometryType() } {
            LABiometryType::TouchID => BiometryKind::TouchId,
            LABiometryType::FaceID => BiometryKind::FaceId,
            _ => BiometryKind::Unknown,
        };

        match can {
            Ok(()) => BiometricAvailability::Available(kind),
            Err(e) => {
                let code = e.code();
                if code == LAError::BiometryNotEnrolled.0 {
                    BiometricAvailability::NotEnrolled(kind)
                } else if code == LAError::BiometryLockout.0 {
                    BiometricAvailability::LockedOut(kind)
                } else {
                    // BiometryNotAvailable, or anything else: no usable hardware.
                    BiometricAvailability::NoHardware
                }
            }
        }
    }

    fn store(&self, account: &str, secret: &[u8]) -> Result<()> {
        // Writing is a replace: re-enabling biometrics must not trip over a
        // stale item, and SecItemAdd refuses duplicates.
        let _ = Self::delete_raw(account);

        let access = Self::access_control()?;
        let data = CFData::from_buffer(secret);

        let mut pairs = Self::base_query(account);
        // Safety: framework-owned constants.
        unsafe {
            pairs.push((constant(kSecValueData), data.as_CFType()));
            pairs.push((constant(kSecAttrAccessControl), access));
        }
        let attributes = CFDictionary::from_CFType_pairs(&pairs);

        // Safety: `attributes` outlives the call; no result is requested.
        let status = unsafe { SecItemAdd(attributes.as_CFTypeRef() as *const _, ptr::null_mut()) };

        match status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(PlatformError::Os("keychain item already exists")),
            // Unsigned builds land here: the entitlement is missing.
            _ => Err(PlatformError::Os("could not write the keychain item")),
        }
    }

    fn load(
        &self,
        account: &str,
        reason: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, BiometricFailure> {
        let mut pairs = Self::base_query(account);
        // Safety: framework-owned constants.
        unsafe {
            pairs.push((
                constant(kSecReturnData),
                core_foundation::boolean::CFBoolean::true_value().as_CFType(),
            ));
            pairs.push((constant(kSecMatchLimit), constant_type(kSecMatchLimitOne)));
            // The sentence the OS shows in the Touch ID sheet.
            pairs.push((
                constant(kSecUseOperationPrompt),
                CFString::new(reason).as_CFType(),
            ));
        }
        let query = CFDictionary::from_CFType_pairs(&pairs);

        let mut result: CFTypeRef = ptr::null();
        // Safety: `query` outlives the call; `result` is +1 on success and is
        // taken under the create rule below.
        let status = unsafe { SecItemCopyMatching(query.as_CFTypeRef() as *const _, &mut result) };

        match status {
            ERR_SEC_SUCCESS if !result.is_null() => {
                // Safety: on success the out-param is a +1 CFDataRef.
                let data = unsafe { CFData::wrap_under_create_rule(result as *const _) };
                Ok(Zeroizing::new(data.to_vec()))
            }
            ERR_SEC_SUCCESS => Err(BiometricFailure::Unavailable),
            ERR_SEC_ITEM_NOT_FOUND => Err(BiometricFailure::NotFound),
            ERR_SEC_USER_CANCELED => Err(BiometricFailure::Cancelled),
            ERR_SEC_AUTH_FAILED => Err(BiometricFailure::NotRecognised),
            // The access control could not be satisfied. The common cause is
            // the enrolment set having changed, which discards the item.
            ERR_SEC_INTERACTION_NOT_ALLOWED => Err(BiometricFailure::Invalidated),
            _ => Err(BiometricFailure::Unavailable),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        match Self::delete_raw(account) {
            // Deleting what is not there is success: disabling biometrics
            // should be idempotent.
            ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            _ => Err(PlatformError::Os("could not delete the keychain item")),
        }
    }

    fn exists(&self, account: &str) -> bool {
        // Ask for the attributes, not the data: `kSecReturnData` would trigger
        // the biometric prompt, and callers use this to decide what to *show*.
        let query = CFDictionary::from_CFType_pairs(&{
            let mut pairs = Self::base_query(account);
            // Safety: framework-owned constant.
            unsafe { pairs.push((constant(kSecMatchLimit), constant_type(kSecMatchLimitOne))) };
            pairs
        });

        // Safety: `query` outlives the call; no result requested.
        let status =
            unsafe { SecItemCopyMatching(query.as_CFTypeRef() as *const _, ptr::null_mut()) };
        status == ERR_SEC_SUCCESS
    }
}
