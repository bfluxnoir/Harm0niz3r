// Define an interface for our app data structure
export interface AppInfo {
  name: string;         // User-friendly name (which will be the bundleName in this case)
  bundleName: string;   // The actual bundle name (namespace)
}

export interface SkillInfo {
  action?: string;
  entity?: string;
  scheme?: string;
  type?: string;
  utd?: string[];
}

export interface ExposedComponent {
  name: string;
  type: string;
  visible: boolean;
  permissionsRequired: string[];
  skills: SkillInfo[];
  // REMOVED: dataShareUri as we are no longer focusing on DataShare specific URIs here
}

export interface AppSurfaceData {
  bundleName: string;
  debugMode: boolean;
  systemApp: boolean;
  requiredAppPermissions: string[];
  exposedComponents: ExposedComponent[];
}

// NEW: Interface for UDMF query result payload
export interface UDMFQueryResult {
  uri: string;
  content: string[];
}

export interface VulnerableAbility {
  app: string;         // bundleName
  ability: string;     // ability name
  skills: SkillInfo[];
  permissions: string[];
}

