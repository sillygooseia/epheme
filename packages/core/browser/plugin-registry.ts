/**
 * EphemePluginRegistry — framework-agnostic browser plugin registry.
 *
 * Zero Angular dependencies — the same pattern as EphemeDeviceController.
 * Angular apps wrap this in an @Injectable service, same as DeviceService wraps EphemeDeviceController.
 *
 * import { EphemePluginRegistry } from '@epheme/core/browser';
 *
 * // In plugin browser entry:
 * export const plugin: EphemeBrowserPlugin = {
 *   id: 'todo',
 *   panels: [{ slot: 'hub.sidebar', component: TodoSidebarComponent }],
 * };
 *
 * // In your Angular plugin.service.ts (one per app):
 * @Injectable({ providedIn: 'root' })
 * export class PluginService {
 *   private readonly _registry = new EphemePluginRegistry();
 *   register(plugin: EphemeBrowserPlugin) { this._registry.register(plugin); }
 *   getSlotComponents(slot: EphemeSlot, features: string[]) { return this._registry.getSlotComponents(slot, features); }
 * }
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyType = new (...args: any[]) => any;

export type EphemeSlot =
  | 'hub.sidebar'
  | 'hub.room.toolbar'
  | 'hub.settings'
  | 'tool.header'
  | 'tool.sidebar';

export interface EphemePluginPanel {
  slot: EphemeSlot;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  component: AnyType;
  requiredFeature?: string;
  order?: number;
}

export interface EphemeBrowserPlugin {
  id: string;
  panels?: EphemePluginPanel[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  routes?: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  providers?: any[];
}

export class EphemePluginRegistry {
  private readonly _plugins = new Map<string, EphemeBrowserPlugin>();

  /**
   * Register a browser plugin. Safe to call multiple times with the same id
   * (re-registration is a no-op and logs a warning).
   */
  register(plugin: EphemeBrowserPlugin): void {
    if (this._plugins.has(plugin.id)) {
      console.warn(`[EphemePluginRegistry] plugin "${plugin.id}" already registered — skipping.`);
      return;
    }
    this._plugins.set(plugin.id, plugin);
  }

  /**
   * Returns components registered for a given slot, filtered by the provided
   * active license features. Components with no requiredFeature are always included.
   * Results are sorted by panel.order (ascending, default 0).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getSlotComponents(slot: EphemeSlot, activeFeatures: string[] = []): AnyType[] {
    const results: { component: AnyType; order: number }[] = [];
    for (const plugin of this._plugins.values()) {
      for (const panel of plugin.panels ?? []) {
        if (panel.slot !== slot) continue;
        if (panel.requiredFeature && !activeFeatures.includes(panel.requiredFeature)) continue;
        results.push({ component: panel.component, order: panel.order ?? 0 });
      }
    }
    results.sort((a, b) => a.order - b.order);
    return results.map(r => r.component);
  }

  /**
   * Returns the merged lazy route config from all registered plugins.
   * Suitable for spreading into the host's provideRouter([...coreRoutes, ...pluginRoutes]).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getRoutes(): any[] {
    const routes: unknown[] = [];
    for (const plugin of this._plugins.values()) {
      routes.push(...(plugin.routes ?? []));
    }
    return routes;
  }

  /**
   * Returns all environment providers contributed by registered plugins. 
   * Pass to the host's bootstrapApplication providers array.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getProviders(): any[] {
    const providers: unknown[] = [];
    for (const plugin of this._plugins.values()) {
      providers.push(...(plugin.providers ?? []));
    }
    return providers;
  }
}
