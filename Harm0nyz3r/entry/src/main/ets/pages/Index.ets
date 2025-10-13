// pages/Index.ets

import { socket } from '@kit.NetworkKit';
import { backgroundTaskManager } from '@kit.BackgroundTasksKit';
import { common, Want, wantAgent, WantAgent } from '@kit.AbilityKit'; // Used for startAbility
import type { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

import { unifiedDataChannel, uniformTypeDescriptor, uniformDataStruct } from '@kit.ArkData'; // ADDED uniformTypeDescriptor, uniformDataStruct
import { notificationManager } from '@kit.NotificationKit'; // For managing notifications (now directly used in UIAbility)


// Define an interface for our app data structure
interface AppInfo {
  name: string;         // User-friendly name (which will be the bundleName in this case)
  bundleName: string;   // The actual bundle name (namespace)
}

interface SkillInfo {
  action?: string;
  entity?: string;
  scheme?: string;
  type?: string;
  utd?: string[];
}

interface ExposedComponent {
  name: string;
  type: string;
  visible: boolean;
  permissionsRequired: string[];
  skills: SkillInfo[];
  // REMOVED: dataShareUri as we are no longer focusing on DataShare specific URIs here
}

interface AppSurfaceData {
  bundleName: string;
  debugMode: boolean;
  systemApp: boolean;
  requiredAppPermissions: string[];
  exposedComponents: ExposedComponent[];
}

// NEW: Interface for UDMF query result payload
interface UDMFQueryResult {
  uri: string;
  content: string[];
}

interface VulnerableAbility {
  app: string;         // bundleName
  ability: string;     // ability name
  skills: SkillInfo[];
  permissions: string[];
}

// New Header Component
@Component
struct Harm0nyz3rHeader {
  build() {
    Column() {
      Row({ space: 16 }) {
        // IMPORTANT: Ensure 'app.media.startIcon' exists in your project.
        // If you don't have this image, replace it with a valid resource or remove.
        // Using a placeholder image for demonstration purposes if app.media.startIcon is not available.
        Image($r('app.media.startIcon'))
          .width(48)
          .height(48)
        Text('Harm0nyz3r')
          .fontSize(32)
          .fontWeight(FontWeight.Bold)
          .fontColor(Color.Black)
          .margin({ top: 6 })
      }
      Text('App Security Tool')
        .fontSize(18)
        .fontWeight(FontWeight.Medium)
        .fontColor(Color.Gray)
        .margin({ top: 2 })
    }
    .alignItems(HorizontalAlign.Center)
    .margin({ top: 28, bottom: 16 }) // Provides vertical spacing for the header
  }
}

@Entry
@Component
struct Index {

  private tcpBuffer: string = "";

  private context = this.getUIContext().getHostContext() as common.UIAbilityContext;
  @State port: string = '51337';
  @State status: string = 'Not running';
  @State isRunning: boolean = false;
  @State appNames: AppInfo[] = []; // This will be the filtered list displayed
  @State allAppNames: AppInfo[] = []; // NEW: This will hold the full list obtained from PC
  @State searchText: string = ''; // NEW: For the search input field

  @State isConnected: boolean = false; // Flag to specify if server is connected

  @State currentPage: 'list' | 'details' | 'vulnerableAbilities' | 'abilityDetails' = 'list';
  @State currentAppDetails: string = '';
  @State selectedAppNamespace: string = '';

  @State currentAppSurfaceJson: string = '';
  @State parsedAppSurface: AppSurfaceData | null = null;
  @State detailsViewMode: 'raw' | 'parsed' = 'raw';
  @State udmfContent: string[] = []; // Existing UDMF content state
  @State udmfStatus: string = ''; // Existing UDMF status state
  @State udmfQueryUri: string = 'udmf://DataHub/bundle/path'; // MODIFIED: Renamed and updated placeholder for UDMF

  //State to get invokable abilities
  @State vulnerableAbilities: VulnerableAbility[] = [];


  @State isLoadingAbilities: boolean = false;

  @State selectedAbility: VulnerableAbility | null = null;
  @State customWantAction: string = '';
  @State customWantEntity: string = '';

  // TCP Server specific states, now directly in UIAbility
  private srv?: socket.TCPSocketServer;
  private serverCli: socket.TCPSocketConnection | undefined = undefined;
  private readonly NOTIFICATION_ID: number = 1001; // Unique ID for the foreground service notification

  onPageShow() {
    hilog.info(0x0000, 'AppLog', 'Page shown, attempting to start server...');
    if (!this.isRunning) {
      this.startServer(); // Automatically try to start the server when the app opens
    }
  }

  async aboutToDisappear() {
    hilog.info(0x0000, 'AppLog', 'Page about to disappear, stopping server...');
    // The stopServer logic is now called explicitly when the app closes or on error,
    // ensuring background tasks are properly managed.
  }

  // --- Reintegrated startServer function ---
  private async startServer(): Promise<void> {
    const p = Number(this.port);
    if (!p || p < 1 || p > 65535) {
      this.status = 'Invalid port';
      this.isRunning = false;
      hilog.error(0x0000, 'AppLog', 'Invalid port specified.');
      return;
    }

    this.status = 'Starting…';
    this.isRunning = false;
    hilog.info(0x0000, 'AppLog', 'Attempting to start TCP server directly in UIAbility.');
    await this.stopServer(); // Ensure any existing server is stopped first

    this.srv = socket.constructTCPSocketServerInstance();
    const addr: socket.NetAddress = { address: '127.0.0.1', port: p };

    try {
      await this.srv.listen(addr);
      this.status = `Listening on ${p} – waiting for console`;
      this.isRunning = true;
      hilog.info(0x0000, 'AppLog', `Server listening on ${p}.`);

      // NEW: Create WantAgentInfo for the UIAbility itself
      let wantAgentInfo: wantAgent.WantAgentInfo = {
        wants: [
          { // Explicitly cast to Want for type inference
            bundleName: this.context.abilityInfo.bundleName,
            abilityName: this.context.abilityInfo.name // This UIAbility's name
          } as Want
        ],
        operationType: wantAgent.OperationType.START_ABILITY,
        requestCode: 0,
        actionFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG] // Correct flag name for wantAgent
      };

      // Obtain the WantAgent object
      let agent: WantAgent;
      try {
        agent = await wantAgent.getWantAgent(wantAgentInfo);
        hilog.info(0x0000, 'AppLog', 'WantAgent obtained successfully for UIAbility.');
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Failed to get WantAgent for UIAbility: ${JSON.stringify(e)}`);
        this.status = `WantAgent Error: ${(e as BusinessError).code}`;
        this.isRunning = false;
        // Ensure notification is cancelled if WantAgent cannot be obtained
        notificationManager.cancel(this.NOTIFICATION_ID);
        return;
      }

      // Promote UIAbility to foreground service using the correct signature
      backgroundTaskManager.startBackgroundRunning(
        this.context,
        backgroundTaskManager.BackgroundMode.DATA_TRANSFER, // Example BackgroundMode enum
        agent // The WantAgent object
      ).then(() => {
        hilog.info(0x0000, 'AppLog', 'UIAbility promoted to foreground service successfully.');
        // Optionally publish a notification manually if the system doesn't do it automatically
        // when using this specific startBackgroundRunning overload.
        notificationManager.publish({
          id: this.NOTIFICATION_ID,
          content: {
            notificationContentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
            normal: {
              title: 'Harm0nyz3r Server',
              text: 'TCP server is running in the background.',
              additionalText: 'Harm0nyz3r TCP Server Running',
            }
          },
          isOngoing: true
        });
      }).catch((err: BusinessError) => {
        hilog.error(0x0000, 'AppLog', `startBackgroundRunning failed Cause: ${JSON.stringify(err)}`);
        this.status = `BgRun Error: ${err.code}`;
        this.isRunning = false;
        // Ensure notification is cancelled if background running fails
        notificationManager.cancel(this.NOTIFICATION_ID);
      });

    } catch (e) {
      this.status = `Listen failed: ${(e as BusinessError).code}`;
      this.isRunning = false;
      hilog.error(0x0000, 'AppLog', `Server listen failed: ${JSON.stringify(e)}`);
      // Ensure notification is cancelled if server fails to start
      notificationManager.cancel(this.NOTIFICATION_ID);
      return;
    }

    this.srv.on('connect', (cli: socket.TCPSocketConnection) => {
      this.serverCli = cli;
      hilog.info(0x0000, 'AppLog', 'Desktop connected.');
      this.status = `Console connected on ${p} (Handshake pending)`;

      cli.on('message', (msg: socket.SocketMessageInfo) => this.handlePacket(cli, msg));
      cli.on('close', () => {
        hilog.info(0x0000, 'AppLog', 'Desktop disconnected.');
        this.serverCli = undefined;
        this.status = `Listening on ${p} – waiting for console`;
        this.appNames = []; // Clear app list when client disconnects
        this.allAppNames = []; // NEW: Clear the full list too
        this.searchText = ''; // NEW: Clear search text
        this.currentPage = 'list'; // Reset to list view
        this.resetDetailsState();
        this.resetQueryState(); // RENAMED
      });
      cli.on('error', (err: BusinessError) => {
        hilog.error(0x0000, 'AppLog', `Client error: ${JSON.stringify(err)}`);
        this.serverCli = undefined;
        this.status = `Client error: ${err.code}`;
      });
    });

    this.srv.on('error', (err: BusinessError) => {
      hilog.error(0x0000, 'AppLog', `Server error: ${JSON.stringify(err)}`);
      this.status = `Server error: ${err.code}`;
      this.isRunning = false;
      this.closeServerResources(); // Stop server on major error
      notificationManager.cancel(this.NOTIFICATION_ID); // Cancel notification on server error
    });
  }

  // --- Reintegrated stopServer function ---
  private async stopServer(): Promise<void> {
    hilog.info(0x0000, 'AppLog', 'Attempting to stop TCP server...');
    this.isConnected = false;
    if (this.serverCli) {
      try {
        await this.serverCli.close();
        hilog.info(0x0000, 'AppLog', 'Closed client connection.');
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Error closing client connection: ${JSON.stringify(e)}`);
      } finally {
        this.serverCli = undefined;
      }
    }
    if (this.srv) {
      try {
        this.srv.off('connect');
        // No srv.close() as it causes issues. Rely on garbage collection/process termination.
        hilog.info(0x0000, 'AppLog', 'Server connect listener removed.');
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Error removing server listener: ${JSON.stringify(e)}`);
      } finally {
        this.srv = undefined;
      }
    }

    // Stop foreground running
    try {
      await backgroundTaskManager.stopBackgroundRunning(this.context); // Re-enabled stopBackgroundRunning
      hilog.info(0x0000, 'AppLog', 'UIAbility stopped foreground running.');
    } catch (e) {
      hilog.error(0x0000, 'AppLog', `Failed to stop background running: ${JSON.stringify(e)}`);
    }

    // Cancel the notification
    try {
      await notificationManager.cancel(this.NOTIFICATION_ID);
      hilog.info(0x0000, 'AppLog', `Notification ${this.NOTIFICATION_ID} cancelled.`);
    } catch (e) {
      hilog.error(0x0000, 'AppLog', `Failed to cancel notification: ${JSON.stringify(e)}`);
    }

    this.status = 'Stopped';
    this.isRunning = false;
    this.isConnected = false;
    this.resetUIState();
    hilog.info(0x0000, 'AppLog', 'TCP server stopped and UIAbility background running ceased.');
  }

  // Helper to close all socket resources (now only called by stopServer)
  private async closeServerResources(): Promise<void> {

    this.isConnected = false;

    // delayId is no longer used with startBackgroundRunning
    if (this.serverCli) {
      try {
        await this.serverCli.close();
        hilog.info(0x0000, 'AppLog', 'Closed client connection.');
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Error closing client connection: ${JSON.stringify(e)}`);
      } finally {
        this.serverCli = undefined;
      }
    }

    if (this.srv) {
      try {
        this.srv.off('connect');
        hilog.info(0x0000, 'AppLog', 'Server connect listener removed.');
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Error removing server listener: ${JSON.stringify(e)}`);
      } finally {
        this.srv = undefined;
      }
    }
  }

  // Handles incoming messages from the desktop client (now directly in UIAbility)
  private async handlePacket(cli: socket.TCPSocketConnection, info: socket.SocketMessageInfo): Promise<void> {
    let dataView = new DataView(info.message);
    let fragment = "";
    for (let i = 0; i < dataView.byteLength; ++i) {
      fragment += String.fromCharCode(dataView.getUint8(i));
    }

    hilog.info(0x0000, 'AppLog', `Received fragment: ${fragment.substring(0, 100)}...`);

    // Acumular en el buffer general
    this.tcpBuffer += fragment;

    // Buscar todos los mensajes completos (separados por \n\n)
    while (this.tcpBuffer.includes('\n\n')) {
      const splitIndex = this.tcpBuffer.indexOf('\n\n');
      const fullMessage = this.tcpBuffer.substring(0, splitIndex);
      this.tcpBuffer = this.tcpBuffer.substring(splitIndex + 2); // saltamos \n\n

      hilog.info(0x0000, 'AppLog', `Full message received: ${fullMessage.substring(0, 100)}...`);
      await this.processFullMessage(cli, fullMessage.trim());
    }
  }

  private async processFullMessage(cli: socket.TCPSocketConnection, txt: string): Promise<void> {

    // Handshake
    if (txt === 'MARCO') {
      await cli.send({ data: 'POLO' });
      this.isConnected = true;
      this.status = `Console connected on ${this.port}`;
      hilog.info(0x0000, 'AppLog', 'Responded with POLO for MARCO handshake.');
      return;
    }

    // Process messages directly as they are no longer forwarded from a service
    if (txt.startsWith('HDC_OUTPUT_ALL_APPS:')) {
      const rawOutput = txt.substring('HDC_OUTPUT_ALL_APPS:'.length);
      this.parseAndDisplayAppList(rawOutput); // This now populates allAppNames and filters into appNames
      const appCount = this.allAppNames.length; // Use allAppNames for total count
      this.status = `App list received (${appCount} apps)`;
      this.currentPage = 'list';
      this.resetDetailsState(); // Reset details state only when a new app list is received
    }
    else if (txt.startsWith('HDC_OUTPUT_APP_DETAILS:')) {
      const detailsOutput = txt.substring('HDC_OUTPUT_APP_DETAILS:'.length);
      this.currentAppDetails = detailsOutput;
      this.currentPage = 'details';
      this.status = `App details received for ${this.selectedAppNamespace || 'an app'}`;
      this.detailsViewMode = 'raw';
      this.resetQueryState(); // RENAMED

    }
    else if (txt.startsWith('HDC_OUTPUT_APP_SURFACE_JSON:')) {
      const jsonOutput = txt.substring('HDC_OUTPUT_APP_SURFACE_JSON:'.length);
      try {
        const parsedData: AppSurfaceData = JSON.parse(jsonOutput);
        this.parsedAppSurface = parsedData;
        this.currentAppSurfaceJson = JSON.stringify(parsedData, null, 2);
        this.currentPage = 'details';
        this.status = `App surface received for ${this.selectedAppNamespace || 'an app'}`;
        this.detailsViewMode = 'parsed';
        this.resetQueryState(); // RENAMED
      } catch (e) {
        const errorMsg = `Failed to parse app surface JSON: ${JSON.stringify(e)}`;
        hilog.error(0x0000, 'AppLog', errorMsg);
        this.currentAppDetails = `Error processing app surface: ${errorMsg}. Received: ${jsonOutput.substring(0, Math.min(jsonOutput.length, 200))}...`;
        this.status = `App surface parse error.`;
        this.currentPage = 'details';
        this.detailsViewMode = 'raw';
        this.resetQueryState(); // RENAMED
      }
    }
    else if (txt.startsWith('HDC_OUTPUT_ERROR:')) {
      const errorOutput = txt.substring('HDC_OUTPUT_ERROR:'.length);
      this.status = `PC reported error: ${errorOutput.substring(0, Math.min(errorOutput.length, 50))}...`;
      this.currentAppDetails = `Error from PC: ${errorOutput}`;
      this.currentPage = 'details';
      this.detailsViewMode = 'raw';
      this.resetQueryState(); // RENAMED
    }
    else if (txt.trim().startsWith('HDC_OUTPUT_EXPOSED_ABILITIES:')) {
      const jsonAbilities = txt.substring('HDC_OUTPUT_EXPOSED_ABILITIES:'.length).trim();
      try {
        const abilities: VulnerableAbility[] = JSON.parse(jsonAbilities);
        this.vulnerableAbilities = abilities;
        this.currentPage = 'vulnerableAbilities';
        this.status = `Received ${this.vulnerableAbilities.length} abilities.`;
        this.isLoadingAbilities = false
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Failed to parse exposed abilities: ${JSON.stringify(e)}`);
        this.status = `Error parsing abilities: ${JSON.stringify(e)}`;
      }
    }

    // --- NEW: Handle COMMAND_REQUEST from Python Client ---
    else if (txt.startsWith('COMMAND_REQUEST:')) {
      const commandPayload = txt.substring('COMMAND_REQUEST:'.length).trim();
      hilog.info(0x0000, 'AppLog', `Received COMMAND_REQUEST: ${commandPayload}`);

      if (commandPayload.startsWith('udmf_query_single_app')) {
        const parts = commandPayload.split(' ');
        if (parts.length >= 2) {
          const namespace = parts[1];
          const groupId = parts.length === 3 ? parts[2] : 'flag'; // Default to 'flag'
          this.handleSingleAppUDMFQuery(namespace, groupId);
        } else {
          this.sendToPcClient('HDC_OUTPUT_ERROR:Invalid udmf_query_single_app command format.');
        }
      } else if (commandPayload.startsWith('udmf_query_all_apps')) {
        const parts = commandPayload.split(' ');
        const groupId = parts.length === 2 ? parts[1] : 'flag'; // Default to 'flag'
        this.handleAllAppsUDMFQuery(groupId);
      }
      // --- NEW: Handle vulnerable abilities response ---
      else if (commandPayload.startsWith('app_visible_abilities')) {
        const parts = commandPayload.split(' ');
        const sendToApp = parts.includes('-a');

        if (sendToApp) {
          this.sendToPcClient('COMMAND_REQUEST:app_visible_abilities -a');
        }
      }
      // --- END NEW ---
      // Add other COMMAND_REQUEST types here if needed in the future
    }
    // --- END NEW ---
    else {
      this.status = `Received partial: ${txt.substring(0, Math.min(txt.length, 50))}...`;
      hilog.info(0x0000, 'AppLog', `Unhandled message: ${txt.substring(0, 50)}...`);
      this.currentAppDetails = this.currentAppDetails + txt;
      this.currentPage = 'details';
      this.detailsViewMode = 'raw';
      this.resetQueryState(); // RENAMED
    }
  }

  // --- Reintegrated Function to send messages to PC client ---
  private async sendToPcClient(message: string): Promise<string> {
    if (!this.serverCli) {
      hilog.warn(0x0000, 'AppLog', 'No PC client connected to send message.');
      return 'ERROR:No PC client connected';
    }
    try {
      await this.serverCli.send({ data: message });
      hilog.info(0x0000, 'AppLog', `Sent to PC: ${message.substring(0, Math.min(message.length, 100))}...`);
      return 'OK';
    } catch (e) {
      hilog.error(0x0000, 'AppLog', `Failed to send to PC: ${JSON.stringify(e)}`);
      return `ERROR:Failed to send to PC: ${JSON.stringify(e)}`;
    }
  }
  // --- END Reintegrated ---

  private resetUIState(): void {
    this.appNames = [];
    this.allAppNames = []; // Reset full list too
    this.searchText = ''; // Reset search text
    this.currentPage = 'list';
    this.resetDetailsState();
    this.resetQueryState(); // RENAMED
  }

  private resetDetailsState(): void {
    this.currentAppDetails = '';
    // IMPORTANT: Keep selectedAppNamespace when on details page, only clear when going back to list
    // this.selectedAppNamespace = ''; // REMOVED THIS LINE
    this.currentAppSurfaceJson = '';
    this.parsedAppSurface = null;
    this.detailsViewMode = 'raw';
  }

  private resetQueryState(): void { // RENAMED: From resetUDMFState
    this.udmfContent = []; // Existing UDMF content state
    this.udmfStatus = ''; // Existing UDMF status state
    //this.udmfQueryUri = 'udmf://DataHub/bundle/path'; // MODIFIED: Reset to a generic UDMF URI placeholder
  }

  /**
   * Parses the raw output of the 'hdc bm dump -a' command,
   * populates `allAppNames` with the full list, and then
   * calls `filterApps` to populate `appNames` based on the current search text.
   * @param rawOutput The raw string output from the hdc command.
   */
  private parseAndDisplayAppList(rawOutput: string): void {
    hilog.info(0x0000, 'AppLog', 'Starting parseAndDisplayAppList with raw string...');
    this.allAppNames = []; // Clear the full list first

    const lines = rawOutput.split('\n');
    const appInfos: AppInfo[] = [];

    const bundleNamePattern = /^\s*([a-zA-Z0-9\._-]+)\s*$/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('ID: ') || line === '') {
        continue;
      }

      const bundleMatch = line.match(bundleNamePattern);

      if (bundleMatch && bundleMatch[1]) {
        const bundleName = bundleMatch[1].trim();
        // FIX: Ensure bundleName is trimmed before pushing to array for robust search
        if (bundleName.includes('.')) {
          appInfos.push({
            name: bundleName,
            bundleName: bundleName.trim() // Ensure no trailing/leading whitespace for bundleName
          });
        }
      }
    }
    this.allAppNames = appInfos.sort((a, b) => a.name.localeCompare(b.name));
    this.filterApps(); // Apply initial filter (which might be empty search)
    if (this.allAppNames.length === 0) {
      this.status = "No applications found or could not parse output.";
    }
  }

  /**
   * Filters the `allAppNames` list based on the `searchText` and
   * updates the `appNames` state, which is displayed in the UI.
   */
  private filterApps(): void {
    if (!this.searchText) {
      this.appNames = [...this.allAppNames]; // Show all if search is empty
    } else {
      const lowerCaseSearchText = this.searchText.toLowerCase();
      this.appNames = this.allAppNames.filter(app =>
      app.name.toLowerCase().includes(lowerCaseSearchText) ||
      app.bundleName.toLowerCase().includes(lowerCaseSearchText)
      );
    }
  }

  private async onRawDetailsTap(bundleName: string): Promise<void> {
    this.selectedAppNamespace = bundleName; // Set the selected app namespace
    this.currentPage = 'details';
    this.currentAppDetails = `Requesting raw details for "${bundleName}" from PC... Please wait.`;
    this.resetQueryState(); // RENAMED
    this.status = `Requesting raw: ${bundleName}`;
    this.detailsViewMode = 'raw';


    const commandToSend = `COMMAND_REQUEST:app_info ${bundleName} -a`;
    const result = await this.sendToPcClient(commandToSend);
    if (result.startsWith('ERROR')) {
      this.currentAppDetails = `Error sending request to PC: ${result.substring('ERROR:'.length)}. Is the PC client connected?`;
      this.status = `Error sending request.`;
    }
  }

  private async onAppSurfaceTap(bundleName: string): Promise<void> {
    this.selectedAppNamespace = bundleName; // Set the selected app namespace
    this.currentPage = 'details';
    this.currentAppDetails = '';
    this.currentAppSurfaceJson = `Requesting parsed app surface for "${bundleName}" from PC... Please wait.`;
    this.resetQueryState(); // This will reset udmfQueryUri to its default
    // MODIFIED: Set udmfQueryUri based on the selected bundleName
    this.udmfQueryUri = `udmf://DataHub/${bundleName}/path`;
    this.status = `Requesting parsed: ${bundleName}`;
    this.detailsViewMode = 'parsed';

    const commandToSend = `COMMAND_REQUEST:app_surface ${bundleName} -a`;
    const result = await this.sendToPcClient(commandToSend);
    if (result.startsWith('ERROR')) {
      this.currentAppSurfaceJson = `Error sending request to PC: ${result.substring('ERROR:'.length)}. Is the PC client connected?`;
      this.status = `Error sending request.`;
    }
  }

  private async onInvokeAbility(namespace: string, abilityName: string): Promise<void> {
    hilog.info(0x0000, 'AppLog', `Attempting to invoke ability: ${abilityName} in bundle ${namespace} directly via ArkTS.`);
    // Log the exact bundleName and abilityName being used
    hilog.info(0x0000, 'AppLog', `Invoking: bundleName='${namespace}', abilityName='${abilityName}'`);
    this.status = `Invoking: ${abilityName}`;

    try {
      const abilityRequest: Want = {
        bundleName: namespace,
        abilityName: abilityName,
      };
      await this.context.startAbility(abilityRequest);
      this.status = `Successfully invoked ${abilityName}.`;
      hilog.info(0x0000, 'AppLog', `Successfully invoked ability: ${abilityName}.`);
    } catch (e) {
      const errorMsg = `Failed to invoke ability ${abilityName}: ${JSON.stringify(e)}`;
      hilog.error(0x0000, 'AppLog', errorMsg);
      this.status = `Invoke failed: ${errorMsg}`;
    }
  }

  private async onInvokeAbilityWithWant(
    app: string,
    ability: string,
    action: string,
    entity: string
  ): Promise<void> {
    this.status = `Invoking ability ${ability} with Want...`;

    // Construimos el comando con el formato esperado
    const commandToSend = `COMMAND_REQUEST:invoke_with_want app=${app} ability=${ability} action=${action} entity=${entity}`;

    try {
      const result = await this.sendToPcClient(commandToSend);
      if (result.startsWith('ERROR')) {
        this.status = `Error invoking ability: ${result.substring('ERROR:'.length)}`;
      } else {
        this.status = `Invoke with Want sent successfully: ${result}`;
      }
    } catch (e) {
      this.status = `Invoke failed: ${e}`;
    }
  }

  private async requestAppListFromPC(): Promise<void> {
    hilog.info(0x0000, 'AppLog', 'Requesting app list from PC client.');
    this.status = 'Requesting app list...';

    const commandToSend = `COMMAND_REQUEST:apps_list -a`;
    const result = await this.sendToPcClient(commandToSend);
    if (result.startsWith('ERROR')) {
      this.status = `App list request error: ${result.substring('ERROR:'.length)}.`;
    }
  }

  /**
   * Queries UDMF content for a given URI using unifiedDataChannel.
   * @param udmfFullUri The full UDMF URI (e.g., "udmf://DataHub/bundle/path").
   */
  private async queryUDMFContent(udmfFullUri: string): Promise<string[]> {
    this.udmfContent = [];
    this.udmfStatus = 'Querying UDMF...';
    hilog.info(0x0000, 'AppLog', `Attempting to query UDMF URI using unifiedDataChannel: ${udmfFullUri}`);

    if (!udmfFullUri) {
      const errorMsg = 'Cannot query UDMF: URI is empty.';
      this.udmfStatus = `Error: ${errorMsg}`;
      hilog.error(0x0000, 'AppLog', errorMsg);
      return []; // Early exit for invalid URI
    }


      const options: unifiedDataChannel.Options = { intention: unifiedDataChannel.Intention.DATA_HUB, key: udmfFullUri };

      // Wrap the callback-based unifiedDataChannel.queryData into a Promise
      const dataList: unifiedDataChannel.UnifiedData[] = await new Promise<unifiedDataChannel.UnifiedData[]>((resolve, reject) => { // FIXED: Explicitly type Promise
        unifiedDataChannel.queryData(options, (err: BusinessError | null, data: unifiedDataChannel.UnifiedData[]) => {
          if (err) {
            hilog.error(0x0000, 'UDMFService', `Error querying UDMF for key ${udmfFullUri} in Promise wrapper: Code: %{public}s, Message: %{public}s, Name: %{public}s, Stack: %{public}s`,
              err.code, err.message, err.name, err.stack);
            reject(err); // Reject the promise on error
          } else {
            resolve(data); // Resolve the promise with data
          }
        });
      });

      const foundContents: string[] = [];
      if (Array.isArray(dataList) && dataList.length > 0) {
        for (let i = 0; i < dataList.length; i++) {
          let records: unifiedDataChannel.UnifiedRecord[] = dataList[i].getRecords();
          for (let j = 0; j < records.length; j++) {
            let types: string[] = records[j].getTypes();
            if (types.includes(uniformTypeDescriptor.UniformDataType.PLAIN_TEXT)) {
              let textObj = records[j].getEntry(uniformTypeDescriptor.UniformDataType.PLAIN_TEXT) as uniformDataStruct.PlainText;
              if (textObj.textContent && textObj.textContent.length > 0) {
                foundContents.push(textObj.textContent);
                hilog.info(0x0000, 'UDMFService', `Found content for key ${udmfFullUri}, record ${j}: %{public}s`, textObj.textContent.substring(0, Math.min(textObj.textContent.length, 50)) + (textObj.textContent.length > 50 ? '...' : ''));
              } else {
                hilog.info(0x0000, 'UDMFService', `PlainText content for key ${udmfFullUri}, record ${j} was empty.`);
              }
            }
          }
        }
        hilog.info(0x0000, 'UDMFService', `Finished querying UDMF for key ${udmfFullUri}. Found ${foundContents.length} items.`);
      } else {
        hilog.info(0x0000, 'UDMFService', `No data list returned for key: ${udmfFullUri}.`);
      }
      return foundContents; // Always return foundContents array on success

  }

  /**
   * Handler for the "Query UDMF Content" button click.
   * Uses the value from the `udmfQueryUri` input field to perform the UDMF query.
   */
  private async onQueryUDMFTap(): Promise<void> { // Removed parameter, now uses state
    this.udmfContent = [];
    this.udmfStatus = 'Querying UDMF...';
    hilog.info(0x0000, 'AppLog', `Querying UDMF for URI from input: ${this.udmfQueryUri}`);

    try {
      const results: string[] = await this.queryUDMFContent(this.udmfQueryUri); // Use udmfQueryUri directly
      if (results.length > 0) {
        this.udmfContent = results;
        this.udmfStatus = `Found ${results.length} UDMF records.`;
      } else {
        this.udmfStatus = 'No UDMF content found for this URI.';
      }
      hilog.info(0x0000, 'AppLog', `UDMF query complete. Status: ${this.udmfStatus}`);
    } catch (e) {
      const errorMsg = `UDMF Query Failed: ${JSON.stringify(e)}`;
      this.udmfStatus = errorMsg;
      hilog.error(0x0000, 'AppLog', errorMsg);
    }
  }

  // --- NEW: handleSingleAppUDMFQuery function ---
  private async handleSingleAppUDMFQuery(namespace: string, groupId: string): Promise<void> {
    hilog.info(0x0000, 'AppLog', `Handling single app UDMF query for ${namespace} with group ID ${groupId}`);
    const udmfUri = `udmf://DataHub/${namespace}/${groupId}`;
    try {
      const content = await this.queryUDMFContent(udmfUri);
      const resultPayload: UDMFQueryResult = { // FIXED: Explicitly type resultPayload
        uri: udmfUri,
        content: content
      };
      this.sendToPcClient(`UDMF_QUERY_RESULT:${JSON.stringify(resultPayload)}`);
    } catch (e) {
      const errorMsg = `Failed to query UDMF for ${namespace}: ${JSON.stringify(e)}`;
      hilog.error(0x0000, 'AppLog', errorMsg);
      this.sendToPcClient(`HDC_OUTPUT_ERROR:${errorMsg}`);
    }
  }
  // --- END NEW ---

  // --- NEW: handleAllAppsUDMFQuery function ---
  private async handleAllAppsUDMFQuery(groupId: string): Promise<void> {
    hilog.info(0x0000, 'AppLog', `Handling all apps UDMF query with group ID ${groupId}`);
    const appsWithContent: AppInfo[] = [];

    // First, get the list of all apps. This will come from the internal `allAppNames` state
    // which is populated by `HDC_OUTPUT_ALL_APPS` from the Python client.
    if (this.allAppNames.length === 0) {
      // If allAppNames is empty, request it from the PC client first.
      // This is a simplified approach; a more robust solution might involve
      // waiting for the list_apps response or having the PC send the list with the command.
      hilog.warn(0x0000, 'AppLog', 'allAppNames is empty. Requesting app list from PC before UDMF query.');
      await this.requestAppListFromPC(); // This will trigger a PC response to populate allAppNames
      // Give a small delay for the app list to be processed, if it's asynchronous
      await new Promise<void>(resolve => setTimeout(resolve, 500)); // FIXED: Explicitly type Promise
    }

    for (const app of this.allAppNames) {
      const udmfUri = `udmf://DataHub/${app.bundleName}/${groupId}`;
      try {
        const content = await this.queryUDMFContent(udmfUri);
        if (content.length > 0) {
          appsWithContent.push(app);
          hilog.info(0x0000, 'AppLog', `Found UDMF content for app: ${app.bundleName}`);
        }
      } catch (e) {
        hilog.error(0x0000, 'AppLog', `Error querying UDMF for app ${app.bundleName}: ${JSON.stringify(e)}`);
        // Continue to next app even if one fails
      }
    }
    this.sendToPcClient(`UDMF_APPS_WITH_CONTENT:${JSON.stringify(appsWithContent)}`);
  }
  // --- END NEW ---

  onBackToList(): void {
    this.currentPage = 'list';
    this.resetDetailsState();
    this.resetQueryState();
    this.status = 'Ready for app list.';
  }

  build() {
    Column() { // Main container column, full width and height
      // 1. App Header
      Harm0nyz3rHeader();

      // 2. Server controls and status section
      Column({ space: 8 }) { // Groups port input, buttons, and status
        // Port input and Start/Stop buttons
        Row({ space: 8 }) { // Arrange elements horizontally
          Text('TCP port:').fontSize(16);
          TextInput({ text: this.port, placeholder: '51337' })
            .type(InputType.Number) // Restricts input to numbers
            .width(80) // Fixed width for the port input field
            .onChange(v => this.port = v);

          Button('Start Server')
            .layoutWeight(1) // Allows button to take available space
            .onClick(() => this.startServer());
          Button('Stop Server')
            .layoutWeight(1) // Allows button to take available space
            .onClick(() => this.stopServer());
        }
        .width('100%') // Ensures the row spans the full full width of its parent
        .padding({ left: 16, right: 16 }); // Horizontal padding for this row

        // Server status indicator and text
        Row({ space: 8 }) {
          Circle()
            .width(10) // Size of the indicator circle
            .height(10)
            .fill(this.isRunning ? Color.Green : Color.Red); // Green if running, Red if not
          Text(`Status: ${this.status}`).fontSize(14);
        }
        .padding({ left: 16, right: 16, bottom: 8 }); // Padding for this status row
      }
      .width('100%'); // Ensures this column spans full width

      Divider().margin({ top: 16, bottom: 16 }); // Separator line

      // 3. Main Content Area (Conditional Rendering using standard if/else if)
      if (this.currentPage === 'list') {
        Column() {
          Button('Get App List from PC')
            .backgroundColor(Color.Blue)
            .fontColor(Color.White)
            .margin({ bottom: 10 })
            .onClick(() => this.requestAppListFromPC());

          // Button to get a list with all callable abilities (those that we're able to open without privileges)
          Button('Get abilities from PC')
            .backgroundColor(Color.Green)
            .fontColor(Color.White)
            .margin({ bottom: 10 })
            .onClick(() => {
              // Due to slowness of request innecessary interactions with server are skipped
              if (this.vulnerableAbilities.length === 0) {
                // No data, send request to server
                this.isLoadingAbilities = true;
                this.sendToPcClient('COMMAND_REQUEST:app_visible_abilities -a');
                this.status = 'Requesting invocable abilities from PC...';
              } else {
                // Already saved data, skip server request
                this.status = 'Using cached invocable abilities.';
              }

              if (this.isConnected) {
                this.currentPage = 'vulnerableAbilities';
              } else {
                this.status = 'You are not connected to PC.';
              }
            });

          // NEW: Search input for app list
          TextInput({ text: this.searchText, placeholder: 'Search apps...' })
            .placeholderColor(Color.Gray)
            .placeholderFont({ size: 14 })
            .backgroundColor(0xFFF8F8F8)
            .borderRadius(8)
            .padding({ left: 10, right: 10, top: 8, bottom: 8 })
            .margin({ bottom: 10, left: 16, right: 16 })
            .onChange(v => {
              this.searchText = v;
              this.filterApps(); // Filter the list as user types
            });

          Text('Installed Applications:')
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .margin({ left: 16, right: 16 });

          Scroll() { // Scrollable area for the app list
            Column() { // Column to hold individual app rows
              if (this.appNames.length === 0 && this.allAppNames.length > 0) { // MODIFIED: Added check for allAppNames
                Text('No applications found matching your search criteria.')
                  .fontSize(12)
                  .fontColor(Color.Gray)
                  .padding(8)
                  .textAlign(TextAlign.Center);
              } else if (this.appNames.length === 0) {
                Text('No applications loaded. Connect to PC and use "Get App List from PC" button or "list_apps -a" in the console.')
                  .fontSize(12)
                  .fontColor(Color.Gray)
                  .padding(8)
                  .textAlign(TextAlign.Center);
              } else {
                ForEach(this.appNames, (app: AppInfo) => { // Iterate over the filtered appNames
                  Row() { // Each app will be a row
                    Text(app.name)
                      .layoutWeight(1) // Take up available space
                      .fontSize(16)
                      .padding({ left: 8 });

                    Button('Info')
                      .width(60)
                      .height(30)
                      .borderRadius(15)
                      .backgroundColor(Color.Brown)
                      .fontColor(Color.White)
                      .margin({ right: 4 })
                      .onClick(() => this.onAppSurfaceTap(app.bundleName));

                    Button('Raw')
                      .width(60)
                      .height(30)
                      .borderRadius(15)
                      .backgroundColor(Color.Orange)
                      .fontColor(Color.White)
                      .onClick(() => this.onRawDetailsTap(app.bundleName));
                  }
                  .width('100%')
                  .padding(4)
                  .margin({ bottom: 4 })
                  .backgroundColor(0xFFE0E0E0)
                  .borderRadius(8);
                });
              }
            }
            .width('100%')
            .padding({ left: 8, right: 8 });
          }
          .width('90%')
          .height('400vp')
          .backgroundColor(0xFFF0F0F0)
          .border({ width: 1, color: Color.Gray, radius: 8 })
          .borderRadius(8);
        }
      }
      else if (this.currentPage === 'vulnerableAbilities') {
        Column() {
          Row(){
            // Back to main view
            Button('← Back to Apps')
              .onClick(() => this.currentPage = 'list')
              .margin({ bottom: 16 });

            Blank().width(12); // Separator

            // Refresh abilities list
            Button('⟳ Refresh')
              .backgroundColor(Color.Grey)
              .fontColor(Color.White)
              .margin({ bottom: 16 })
              .onClick(() => {
                // Clean up list and send request
                if (this.isConnected) {
                  this.isLoadingAbilities = true;
                  this.vulnerableAbilities = [];
                  this.sendToPcClient('COMMAND_REQUEST:app_visible_abilities -a');
                  this.status = 'Refreshing invocable abilities from PC...';
                }
                else {
                  this.status = 'You are not connected to PC.';
                }
              });
          }
          // Title
          Text('Invocable Abilities')
            .fontSize(20)
            .fontWeight(FontWeight.Bold)
            .margin({ top: 16, bottom: 16 });

          if (this.isLoadingAbilities) {
            Row() {
              LoadingProgress()
                .width(20)
                .height(20)
                .margin({ top: 16, right: 8 });
              Text('Loading ability list...')
                .fontSize(14)
                .fontColor(Color.Grey);
            }
            .margin({ bottom: 16 });
          }
          else {

          }

          // Lista
          Scroll() {
            Column() {
              ForEach(this.vulnerableAbilities, (ability: VulnerableAbility) => {
                Row() {
                  Column() {
                    Text(ability.ability)
                      .fontSize(16)
                      .fontWeight(FontWeight.Medium);
                    Text(ability.app)
                      .fontSize(12)
                      .fontColor(Color.Gray);
                  }
                  .layoutWeight(1);

                  Button('Info')
                    .width(60)
                    .backgroundColor(Color.Blue)
                    .margin({ right: 8 }) // Space between buttons
                    .onClick(() => {
                      this.selectedAbility = ability;
                      this.currentPage = 'abilityDetails';
                    });
                  Button('Invoke')
                    .width(80)
                    .backgroundColor(Color.Green)
                    .onClick(() => this.onInvokeAbility(ability.app, ability.ability)); // <-- Usa las propiedades correctas
                }
                .padding(12)
                .margin({ bottom: 10 })
                .backgroundColor(0xFFF5F5F5)
                .borderRadius(8);
              })
            }
          }
          .height('55%');
        }
        .padding(16)
      }
      else if (this.currentPage === 'details') {
        Column() {
          Button('Back to App List')
            .onClick(() => this.onBackToList())
            .margin({ bottom: 10 });

          Text(`Details for: ${this.selectedAppNamespace}`)
            .fontSize(18)
            .fontWeight(FontWeight.Medium)
            .margin({ bottom: 5 });

          Row({ space: 8 }) {
            Button('Show Raw Dump')
              .backgroundColor(this.detailsViewMode === 'raw' ? Color.Blue : Color.Gray)
              .fontColor(Color.White)
              .onClick(() => this.detailsViewMode = 'raw');
            Button('Show Parsed Info')
              .backgroundColor(this.detailsViewMode === 'parsed' ? Color.Blue : Color.Gray)
              .fontColor(Color.White)
              .onClick(() => this.detailsViewMode = 'parsed');
          }
          .margin({ bottom: 10 });

          Scroll() {
            if (this.detailsViewMode === 'raw') {
              Text(this.currentAppDetails)
                .fontSize(16)
                .padding(10)
                .backgroundColor(0xFFF0F0F0)
                .borderRadius(5)
                .width('100%')
                .textAlign(TextAlign.Start);
            } else {
              if (this.parsedAppSurface) {
                Column() {
                  Text(`App Name: ${this.parsedAppSurface.bundleName}`)
                    .fontSize(20)
                    .fontWeight(FontWeight.Bold)
                    .margin({ bottom: 8 });
                  Text(`Debug Mode: ${this.parsedAppSurface.debugMode ? 'Yes' : 'No'}`)
                    .fontSize(16);
                  Text(`System App: ${this.parsedAppSurface.systemApp ? 'Yes' : 'No'}`)
                    .fontSize(16)
                    .margin({ bottom: 16 });

                  if (this.parsedAppSurface.requiredAppPermissions && this.parsedAppSurface.requiredAppPermissions.length > 0) {
                    Text('Overall Required Permissions:')
                      .fontSize(18)
                      .fontWeight(FontWeight.Bold)
                      .margin({ bottom: 8 });
                    ForEach(this.parsedAppSurface.requiredAppPermissions, (perm: string) => {
                      Text(`- ${perm}`).fontSize(14).fontColor(Color.Black);
                    });
                    Divider().margin({ top: 16, bottom: 16 });
                  }

                  // NEW: Query UDMF URI input field
                  Row({ space: 8 }) {
                    Text('Query URI:').fontSize(16);
                    TextInput({ text: this.udmfQueryUri, placeholder: 'udmf://DataHub/bundle/path' }) // MODIFIED: Use udmfQueryUri
                      .placeholderColor(Color.Gray)
                      .placeholderFont({ size: 14 })
                      .backgroundColor(0xFFF8F8F8)
                      .borderRadius(8)
                      .padding({ left: 10, right: 10, top: 8, bottom: 8 })
                      .layoutWeight(1)
                      .onChange(v => this.udmfQueryUri = v); // MODIFIED: Bind to udmfQueryUri
                  }
                  .margin({ bottom: 10 });

                  Button('Query UDMF Content') // MODIFIED: Button text
                    .backgroundColor(Color.Green)
                    .fontColor(Color.White)
                    .margin({ bottom: 10 })
                    .onClick(() => this.onQueryUDMFTap()); // MODIFIED: Call onQueryUDMFTap without args

                  if (this.udmfStatus) {
                    Text(`UDMF Status: ${this.udmfStatus}`)
                      .fontSize(14)
                      .fontColor(this.udmfStatus.includes('Error') ? Color.Red : Color.Black)
                      .margin({ bottom: 8 });
                  }

                  if (this.udmfContent.length > 0) {
                    Text('UDMF Content Found:')
                      .fontSize(16)
                      .fontWeight(FontWeight.Bold)
                      .margin({ bottom: 8 });
                    ForEach(this.udmfContent, (content: string, index: number) => {
                      Text(`${index + 1}. ${content}`)
                        .fontSize(14)
                        .fontColor(Color.Gray)
                        .margin({ bottom: 4 });
                    });
                    Divider().margin({ top: 16, bottom: 16 });
                  }

                  Text('Exposed Components:')
                    .fontSize(18)
                    .fontWeight(FontWeight.Bold)
                    .margin({ bottom: 8 });

                  if (this.parsedAppSurface.exposedComponents.length === 0) {
                    Text('No exposed abilities or extensions found.')
                      .fontSize(14)
                      .fontColor(Color.Gray);
                  } else {
                    ForEach(this.parsedAppSurface.exposedComponents, (component: ExposedComponent) => {
                      Column() {
                        Row() {
                          Text(`Name: ${component.name}`)
                            .layoutWeight(1)
                            .fontSize(16)
                            .fontWeight(FontWeight.Medium);
                          if (component.type.includes('Ability') && component.visible) {
                            Button('Invoke')
                              .width(80)
                              .height(30)
                              .borderRadius(15)
                              .backgroundColor(Color.Green)
                              .fontColor(Color.White)
                              .onClick(() => this.onInvokeAbility(this.parsedAppSurface!.bundleName, component.name)); // MODIFIED: Added non-null assertion '!'
                          }
                          // REMOVED: The DataShare-specific button logic for extensions
                        }
                        .width('100%')
                        .margin({ bottom: 4 });

                        Text(`Type: ${component.type}`).fontSize(14).fontColor(Color.Gray);
                        Text(`Visible: ${component.visible ? 'Yes' : 'No'}`).fontSize(14).fontColor(Color.Gray);

                        // REMOVED: Display dataShareUri if available

                        if (component.permissionsRequired && component.permissionsRequired.length > 0) {
                          Text('Permissions Required:').fontSize(14).fontWeight(FontWeight.Medium).margin({ top: 4 });
                          ForEach(component.permissionsRequired, (perm: string) => {
                            Text(`- ${perm}`).fontSize(12).fontColor(Color.Gray);
                          });
                        }

                        if (component.skills && component.skills.length > 0) {
                          Text('Skills (Intent Filters):').fontSize(14).fontWeight(FontWeight.Medium).margin({ top: 4 });
                          ForEach(component.skills, (skill: SkillInfo) => {
                            Column() {
                              if (skill.action) { Text(`  Action: ${skill.action}`).fontSize(12).fontColor(Color.Gray); }
                              if (skill.entity) { Text(`  Entity: ${skill.entity}`).fontSize(12).fontColor(Color.Gray); }
                              if (skill.scheme) { Text(`  Scheme: ${skill.scheme}`).fontSize(12).fontColor(Color.Gray); }
                              if (skill.type) { Text(`  Type: ${skill.type}`).fontSize(12).fontColor(Color.Gray); }
                              if (skill.utd && skill.utd.length > 0) { Text(`  UTD: ${skill.utd.join(', ')}`).fontSize(12).fontColor(Color.Gray); }
                            }
                            .alignItems(HorizontalAlign.Start)
                            .margin({ bottom: 2 });
                          });
                        }
                      }
                      .alignItems(HorizontalAlign.Start)
                      .width('100%')
                      .padding(8)
                      .margin({ bottom: 8 })
                      .backgroundColor(0xFFE0E0E0)
                      .borderRadius(8);
                    });
                  }
                  Button('View Raw Parsed JSON')
                    .margin({ top: 16 })
                    .backgroundColor(Color.Blue)
                    .fontColor(Color.White)
                    .onClick(() => {
                      this.currentAppDetails = this.currentAppSurfaceJson;
                      this.detailsViewMode = 'raw';
                    });

                }
                .alignItems(HorizontalAlign.Start)
                .width('100%')
                .padding(10);
              }

              else {
                Text('No parsed app surface data available. Please click "Info" button for an app.')
                  .fontSize(16)
                  .fontColor(Color.Gray)
                  .padding(10)
                  .textAlign(TextAlign.Center);
              }
            }
          }
          .width('90%')
          .height('400vp')
          .backgroundColor(0xFFF0F0F0)
          .border({ width: 1, color: Color.Gray, radius: 8 })
          .borderRadius(8);
        }
      }
      else if (this.currentPage === 'abilityDetails' && this.selectedAbility) {
        Column() {
          // Button to return to ability list
          Button('← Back to abilities')
            .onClick(() => {
              this.currentPage = 'vulnerableAbilities';
              this.selectedAbility = null;
            })
            .margin({ bottom: 16 });

          // Title
          Text('Ability Details')
            .fontSize(20)
            .fontWeight(FontWeight.Bold)
            .margin({ bottom: 16 });

          // Basic Info.
          Text(`App: ${this.selectedAbility.app}`)
            .fontSize(14)
            .fontWeight(FontWeight.Bold)
            .margin({ bottom: 8 });

          Text(`Ability: ${this.selectedAbility.ability}`)
            .fontSize(14)
            .fontWeight(FontWeight.Bold)
            .margin({ bottom: 10 });

          // Show Skill if any
          Text(`Skills:`)
            .fontSize(14)
            .fontWeight(FontWeight.Bold)
            .margin({ bottom: 5 });
          if (this.selectedAbility.skills.length > 0) {
            Scroll() {
              Column() {
                ForEach(this.selectedAbility.skills, (skill: SkillInfo) => {
                  Column() {
                    Text(`• Action: ${skill.action}`)
                      .fontSize(13)
                      .fontWeight(FontWeight.Bold)
                      .textAlign(TextAlign.Start)
                      .margin({ bottom: 2 });

                    Text(`  Entity: ${skill.entity}`)
                      .fontSize(13)
                      .textAlign(TextAlign.Start);

                    Text(`  Scheme: ${skill.scheme}`)
                      .fontSize(13)
                      .textAlign(TextAlign.Start);

                    Text(`  Type: ${skill.type}`)
                      .fontSize(13)
                      .textAlign(TextAlign.Start);
                  }
                })
              }
              .margin({ bottom: 5 })
            }
            .padding(20)
            .borderRadius(6)
            .backgroundColor(0xFFF0F0F0)
            .margin({ bottom: 10 })
            .height('20%');
          } else {
            Text('No skills associated.')
              .fontSize(13)
              .fontColor(Color.Gray)
              .margin({ bottom: 16 });
          }

          // Separator
          Divider().margin({ top: 16, bottom: 16 });

          // Text fields to pass want parameters
          // TODO: Rework this input
          Text('Launch Want')
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .margin({ bottom: 8 });

          TextInput({ placeholder: 'Action' })
            .onChange(value => this.customWantAction = value)
            .margin({ bottom: 8 });

          TextInput({ placeholder: 'Entity' })
            .onChange(value => this.customWantEntity = value)
            .margin({ bottom: 8 });

          Button('Invoke with Want')
            .backgroundColor(Color.Green)
            .onClick(() => {
              if (this.selectedAbility) {
                this.onInvokeAbilityWithWant(
                  this.selectedAbility.app,
                  this.selectedAbility.ability,
                  this.customWantAction || '',
                  this.customWantEntity || ''
                );
              }
            });
        }
        .padding(16)
      }
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Start);
  }
}
