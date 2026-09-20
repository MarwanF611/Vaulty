/**
 * Typed wrappers over the Tauri command surface.
 *
 * Everything the frontend can ask for is in this file. Note what is *not* here:
 * there is no way to get a list of secrets, and no way to get a secret without
 * naming one entry and calling `revealSecret` or `copySecret` explicitly. That
 * mirrors the Rust side (src-tauri/src/commands.rs).
 */
import { invoke } from '@tauri-apps/api/core';
import type {
  BiometricState,
  SnapshotInfo,
  BiometricUnlockOutcome,
  CaptureState,
  EntryMeta,
  NewEntryInput,
  PermissionState,
  RevealedSecret,
  SaveCaptureInput,
  Settings,
  UpdateEntryInput,
  VaultStatus
} from './types';

export const vaultStatus = () => invoke<VaultStatus>('vault_status');

export const createVault = (password: string) =>
  invoke<VaultStatus>('create_vault', { password });

export const unlockVault = (password: string) =>
  invoke<VaultStatus>('unlock_vault', { password });

export const lockVault = () => invoke<void>('lock_vault');

export const changeMasterPassword = (oldPassword: string, newPassword: string) =>
  invoke<void>('change_master_password', { oldPassword, newPassword });

export const listEntries = () => invoke<EntryMeta[]>('list_entries');

export const searchEntries = (query: string) =>
  invoke<EntryMeta[]>('search_entries', { query });

export const addEntry = (input: NewEntryInput) =>
  invoke<EntryMeta>('add_entry', { input });

export const updateEntry = (id: string, input: UpdateEntryInput) =>
  invoke<EntryMeta>('update_entry', { id, input });

export const deleteEntry = (id: string) => invoke<void>('delete_entry', { id });

/**
 * Decrypt and return one secret. The user pressed "reveal".
 *
 * The caller owns the lifetime of what comes back: show it, then drop it.
 */
export const revealSecret = (id: string) =>
  invoke<RevealedSecret>('reveal_secret', { id });

/**
 * Copy one secret to the clipboard.
 *
 * Returns nothing on purpose — the copy happens in Rust, so the plaintext never
 * enters the webview at all.
 */
export const copySecret = (id: string) => invoke<void>('copy_secret', { id });

export const takeSnapshot = () => invoke<string>('take_snapshot');

export const exportEncrypted = (targetPath: string, exportPassword: string) =>
  invoke<void>('export_encrypted', { targetPath, exportPassword });

// ------------------------------------------------------------ Phase 2

export const captureState = () => invoke<CaptureState>('capture_state');

/**
 * Show the captured text.
 *
 * The sibling of `revealSecret`. The capture is the user's own selection, but
 * it is still plaintext, so it crosses the boundary only when asked for.
 */
export const revealCapture = () => invoke<string>('reveal_capture');

/**
 * Save the pending capture as a new entry.
 *
 * The secret is not a parameter: it never leaves Rust. The popup supplies a
 * label, tags and kind, and the captured text is taken from app state.
 */
export const saveCapture = (input: SaveCaptureInput) =>
  invoke<EntryMeta>('save_capture', { input });

export const discardCapture = () => invoke<void>('discard_capture');

export const hidePopup = () => invoke<void>('hide_popup');

export const permissionState = () => invoke<PermissionState>('permission_state');

export const requestAccessibility = () => invoke<PermissionState>('request_accessibility');

export const openAccessibilitySettings = () =>
  invoke<void>('open_accessibility_settings');

export const getSettings = () => invoke<Settings>('get_settings');

export const setShortcut = (accelerator: string) =>
  invoke<Settings>('set_shortcut', { accelerator });

export const setClipboardClearSeconds = (seconds: number) =>
  invoke<Settings>('set_clipboard_clear_seconds', { seconds });

// ------------------------------------------------------------ Phase 3

export const biometricState = () => invoke<BiometricState>('biometric_state');

/**
 * Turn on biometric unlock.
 *
 * Takes the master password even though the vault is open: adding a second way
 * in should cost the credential it sits alongside.
 */
export const enableBiometrics = (password: string) =>
  invoke<BiometricState>('enable_biometrics', { password });

export const disableBiometrics = () => invoke<BiometricState>('disable_biometrics');

/**
 * Unlock with Touch ID. Raises the system prompt.
 *
 * Every failure rejects — there is no silent unlock. Callers show the password
 * field on any error.
 */
export const unlockWithBiometrics = () =>
  invoke<BiometricUnlockOutcome>('unlock_with_biometrics');

// ------------------------------------------------------------ Phase 5

export const setIdleLockSeconds = (seconds: number) =>
  invoke<Settings>('set_idle_lock_seconds', { seconds });

/**
 * Snapshots, newest first.
 *
 * Works on a vault too corrupt to open — which is the case it exists for.
 */
export const listSnapshots = () => invoke<SnapshotInfo[]>('list_snapshots');

/** Replace the live vault with a snapshot. Locks first; keeps the old file. */
export const restoreSnapshot = (index: number) =>
  invoke<VaultStatus>('restore_snapshot', { index });

export const snapshotNow = () => invoke<SnapshotInfo[]>('snapshot_now');
