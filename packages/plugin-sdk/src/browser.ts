/**
 * Browser-side plugin interface for Epheme Angular host applications.
 *
 * A browser plugin contributes UI panels, lazy routes, and DI providers
 * to the host application without the host needing to know anything about
 * the plugin's implementation.
 *
 * Angular-only in v1. React/Vue adapters deferred.
 */

/**
 * Named slots where plugins can inject UI components.
 * The host application places <epheme-plugin-slot> elements at these locations.
 */
export type EphemeSlot =
  // Hub application slots
  | 'hub.sidebar'        // Left navigation area in Hub
  | 'hub.room.toolbar'   // Per-room toolbar actions row
  | 'hub.settings'       // Settings page panel sections

  // Generic tool application slots
  | 'tool.header'        // Application header / toolbar area
  | 'tool.sidebar';      // Application sidebar

/**
 * A single panel contribution — one component in one slot.
 */
export interface EphemePluginPanel {
  /** Which slot this component occupies */
  slot: EphemeSlot;

  /**
   * Angular component class. Must be standalone.
   * Will be created dynamically via ViewContainerRef.createComponent().
   * The component's DI tree is the host app's — it can inject DeviceService,
   * LicenseService, Router, etc. from the host.
   */
  // Using unknown here so the SDK has no Angular peer dep.
  // The plugin registry casts to Type<unknown> internally.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  component: any;

  /**
   * If set, the host will only render this panel when the active license
   * includes this feature. Checked via EphemeLicenseController.hasFeature().
   */
  requiredFeature?: string;

  /** Display order within the slot. Lower numbers rendered first. Defaults to 0. */
  order?: number;
}

/**
 * EphemeBrowserPlugin — the interface a plugin package's browser entry must satisfy.
 *
 * @example
 * // browser/index.ts
 * import { EphemeBrowserPlugin } from '@epheme/plugin-sdk';
 * import { TodoSidebarComponent } from './sidebar.component';
 *
 * export const plugin: EphemeBrowserPlugin = {
 *   id: 'todo',
 *   panels: [
 *     { slot: 'hub.sidebar', component: TodoSidebarComponent },
 *   ],
 *   routes: [
 *     { path: 'todo', loadComponent: () => import('./todo.component').then(m => m.TodoComponent) },
 *   ],
 * };
 */
export interface EphemeBrowserPlugin {
  /** Must match the pluginId in the manifest */
  id: string;

  /** UI components injected into named host slots */
  panels?: EphemePluginPanel[];

  /**
   * Angular lazy routes contributed to the host router.
   * Routes are merged into the host's router config at the root level.
   * Typed as unknown[] to avoid Angular peer dep in this package.
   */
  routes?: unknown[];

  /**
   * Angular environment providers contributed to the host's root injector.
   * Use this to register plugin-specific services, HTTP interceptors, etc.
   * Typed as unknown[] to avoid Angular peer dep in this package.
   */
  providers?: unknown[];
}
