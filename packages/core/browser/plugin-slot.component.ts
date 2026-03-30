/**
 * EphemePluginSlotComponent — renders all plugin components registered for a named slot.
 *
 * Place this element anywhere in a host Angular template to create a plugin injection point.
 *
 * @example
 * <!-- In hub.component.html -->
 * <epheme-plugin-slot name="hub.sidebar" [activeFeatures]="licenseFeatures()" />
 *
 * Components rendered here are created dynamically via ViewContainerRef.createComponent().
 * Each component runs inside the host app's Angular DI tree, so plugins can inject
 * DeviceService, LicenseService, Router, etc. directly.
 *
 * If no plugins contribute to the slot, this element renders nothing.
 */

import {
  Component,
  Input,
  OnChanges,
  ViewContainerRef,
  ComponentRef,
  OnDestroy,
  ChangeDetectionStrategy,
  inject,
} from '@angular/core';
import { EphemePluginRegistry, EphemeSlot } from './plugin-registry';

@Component({
  selector: 'epheme-plugin-slot',
  standalone: true,
  template: '', // components are rendered into the ViewContainerRef, not this template
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EphemePluginSlotComponent implements OnChanges, OnDestroy {
  @Input({ required: true }) name!: EphemeSlot;
  @Input() activeFeatures: string[] = [];

  private readonly _registry = inject(EphemePluginRegistry);
  private readonly _vcr = inject(ViewContainerRef);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private _refs: ComponentRef<any>[] = [];

  ngOnChanges(): void {
    this._render();
  }

  ngOnDestroy(): void {
    this._clear();
  }

  private _render(): void {
    this._clear();
    const components = this._registry.getSlotComponents(this.name, this.activeFeatures);
    for (const component of components) {
      const ref = this._vcr.createComponent(component);
      this._refs.push(ref);
    }
  }

  private _clear(): void {
    for (const ref of this._refs) {
      ref.destroy();
    }
    this._refs = [];
    this._vcr.clear();
  }
}
