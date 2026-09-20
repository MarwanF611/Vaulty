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
  EntryMeta,
  NewEntryInput,
  RevealedSecret,
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
