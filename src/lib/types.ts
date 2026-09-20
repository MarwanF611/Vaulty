export type EntryKind = 'password' | 'code' | 'note' | 'card' | 'wifi';

export const ENTRY_KINDS: EntryKind[] = ['password', 'code', 'note', 'card', 'wifi'];

export interface VaultStatus {
  exists: boolean;
  locked: boolean;
  path: string;
  vaultId: string | null;
  formatVersion: number | null;
  entryCount: number | null;
}

/** Metadata only. This is everything the frontend is allowed to hold. */
export interface EntryMeta {
  id: string;
  label: string;
  tags: string[];
  kind: EntryKind;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
}

/**
 * The one plaintext-bearing shape in the app.
 *
 * Obtained only from `revealSecret`, only when the user presses reveal. Hold it
 * in a local variable for as long as it is on screen and drop it after — never
 * put it in a store, never log it, never persist it.
 */
export interface RevealedSecret {
  secret: string;
  note: string | null;
}

export interface NewEntryInput {
  label: string;
  tags: string[];
  kind: EntryKind;
  secret: string;
  note?: string | null;
}

export interface UpdateEntryInput {
  label?: string;
  tags?: string[];
  kind?: EntryKind;
  secret?: string;
  /** Omit to leave alone; pass null to clear. */
  note?: string | null;
}

/** Matches `CmdError` in src-tauri/src/error.rs. */
export interface CmdError {
  code:
    | 'auth'
    | 'locked'
    | 'not_found'
    | 'vault_not_found'
    | 'corrupt'
    | 'unsupported_version'
    | 'invalid'
    | 'no_slot'
    | 'storage'
    | 'io'
    | 'internal'
    // Phase 2. `shortcut_taken` means another application holds the binding and
    // the previous one was rolled back; `no_capture` means the pending capture
    // expired or was already consumed.
    | 'shortcut_invalid'
    | 'shortcut_taken'
    | 'no_capture';
  message: string;
}

export function isCmdError(e: unknown): e is CmdError {
  return typeof e === 'object' && e !== null && 'code' in e && 'message' in e;
}

export function errorMessage(e: unknown): string {
  if (isCmdError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return 'Something went wrong.';
}

// ------------------------------------------------------------ Phase 2

export type PopupMode = 'capture' | 'search' | 'permission_required';

/**
 * Sent to the popup when the global shortcut fires.
 *
 * Note what is absent: the captured text. The popup gets a character count so
 * it can render a masked preview, and must call `revealCapture` to see more.
 */
export interface CapturePayload {
  mode: PopupMode;
  charCount: number | null;
  locked: boolean;
  permission: PermissionStatus;
  elapsedMs: number;
  captureMs: number | null;
  clipboardRestored: boolean;
}

export type PermissionStatus = 'granted' | 'denied' | 'not_required' | 'unsupported';

export interface CaptureState {
  hasCapture: boolean;
  charCount: number | null;
  locked: boolean;
  lastCaptureMs: number | null;
}

export interface SaveCaptureInput {
  label: string;
  tags: string[];
  kind: EntryKind;
  note?: string | null;
}

export interface PermissionState {
  accessibility: PermissionStatus;
  captureSupported: boolean;
}

export interface Settings {
  shortcut: string;
  clipboardClearSeconds: number;
  defaultShortcut: string;
}

/** The event name the popup listens on. Must match popup.rs. */
export const CAPTURE_EVENT = 'vaulty://capture';
