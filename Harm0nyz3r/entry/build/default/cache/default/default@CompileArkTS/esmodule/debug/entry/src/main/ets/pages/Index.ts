if (!("finalizeConstruction" in ViewPU.prototype)) {
    Reflect.set(ViewPU.prototype, "finalizeConstruction", () => { });
}
interface Index_Params {
    abilitiesSearchText?: string;
    tcpBuffer?: string;
    context?;
    port?: string;
    status?: string;
    isRunning?: boolean;
    appNames?: AppInfo[];
    allAppNames?: AppInfo[];
    searchText?: string;
    isConnected?: boolean;
    currentPage?: 'list' | 'details' | 'vulnerableAbilities' | 'abilityDetails';
    currentAppDetails?: string;
    selectedAppNamespace?: string;
    currentAppSurfaceJson?: string;
    parsedAppSurface?: AppSurfaceData | null;
    detailsViewMode?: 'raw' | 'parsed';
    udmfContent?: string[];
    udmfStatus?: string;
    udmfQueryUri?: string;
    vulnerableAbilities?: VulnerableAbility[];
    filteredVulnerableAbilities?: VulnerableAbility[];
    isLoadingAbilities?: boolean;
    selectedAbility?: VulnerableAbility | null;
    customWantAction?: string;
    customWantEntity?: string;
    srv?: socket.TCPSocketServer;
    serverCli?: socket.TCPSocketConnection | undefined;
    NOTIFICATION_ID?: number;
}
import socket from "@ohos:net.socket";
import backgroundTaskManager from "@ohos:resourceschedule.backgroundTaskManager";
import type common from "@ohos:app.ability.common";
import type Want from "@ohos:app.ability.Want";
import wantAgent from "@ohos:app.ability.wantAgent";
import type { WantAgent as WantAgent } from "@ohos:app.ability.wantAgent";
import type { BusinessError as BusinessError } from "@ohos:base";
import hilog from "@ohos:hilog";
import unifiedDataChannel from "@ohos:data.unifiedDataChannel";
import uniformTypeDescriptor from "@ohos:data.uniformTypeDescriptor";
import type uniformDataStruct from "@ohos:data.uniformDataStruct";
import notificationManager from "@ohos:notificationManager";
import type { AppInfo, AppSurfaceData, ExposedComponent, SkillInfo, UDMFQueryResult, VulnerableAbility } from '../interfaces/interfaces';
import { Harm0nyz3rHeader } from "@normalized:N&&&entry/src/main/ets/components/Harm0niz3rHeader&";
import { BackButton, InfoButton, InvokeButton, RefreshButton } from "@normalized:N&&&entry/src/main/ets/components/Buttons&";
import { LoadingIcon } from "@normalized:N&&&entry/src/main/ets/components/LoadingIcon&";
import { IndicatorCircle } from "@normalized:N&&&entry/src/main/ets/components/IndicatorCircle&";
import router from "@ohos:router";
import { executeCommand, processShellCommand } from "@normalized:Y&&&libentry.so&";
import fileIo from "@ohos:file.fs";
class Index extends ViewPU {
    constructor(parent, params, __localStorage, elmtId = -1, paramsLambda = undefined, extraInfo) {
        super(parent, __localStorage, elmtId, extraInfo);
        if (typeof paramsLambda === "function") {
            this.paramsGenerator_ = paramsLambda;
        }
        this.abilitiesSearchText = "";
        this.tcpBuffer = "";
        this.context = this.getUIContext().getHostContext() as common.UIAbilityContext;
        this.__port = new ObservedPropertySimplePU('51337', this, "port");
        this.__status = new ObservedPropertySimplePU('Not running', this, "status");
        this.__isRunning = new ObservedPropertySimplePU(false, this, "isRunning");
        this.__appNames = new ObservedPropertyObjectPU([], this, "appNames");
        this.__allAppNames = new ObservedPropertyObjectPU([], this, "allAppNames");
        this.__searchText = new ObservedPropertySimplePU('', this, "searchText");
        this.__isConnected = new ObservedPropertySimplePU(false, this, "isConnected");
        this.__currentPage = new ObservedPropertySimplePU('list', this, "currentPage");
        this.__currentAppDetails = new ObservedPropertySimplePU('', this, "currentAppDetails");
        this.__selectedAppNamespace = new ObservedPropertySimplePU('', this, "selectedAppNamespace");
        this.__currentAppSurfaceJson = new ObservedPropertySimplePU('', this, "currentAppSurfaceJson");
        this.__parsedAppSurface = new ObservedPropertyObjectPU(null, this, "parsedAppSurface");
        this.__detailsViewMode = new ObservedPropertySimplePU('raw', this, "detailsViewMode");
        this.__udmfContent = new ObservedPropertyObjectPU([], this, "udmfContent");
        this.__udmfStatus = new ObservedPropertySimplePU('', this, "udmfStatus");
        this.__udmfQueryUri = new ObservedPropertySimplePU('udmf://DataHub/bundle/path', this, "udmfQueryUri");
        this.__vulnerableAbilities = new ObservedPropertyObjectPU([], this, "vulnerableAbilities");
        this.__filteredVulnerableAbilities = new ObservedPropertyObjectPU([], this, "filteredVulnerableAbilities");
        this.__isLoadingAbilities = new ObservedPropertySimplePU(false, this, "isLoadingAbilities");
        this.__selectedAbility = new ObservedPropertyObjectPU(null, this, "selectedAbility");
        this.__customWantAction = new ObservedPropertySimplePU('', this, "customWantAction");
        this.__customWantEntity = new ObservedPropertySimplePU('', this, "customWantEntity");
        this.srv = undefined;
        this.serverCli = undefined;
        this.NOTIFICATION_ID = 1001;
        this.setInitiallyProvidedValue(params);
        this.finalizeConstruction();
    }
    setInitiallyProvidedValue(params: Index_Params) {
        if (params.abilitiesSearchText !== undefined) {
            this.abilitiesSearchText = params.abilitiesSearchText;
        }
        if (params.tcpBuffer !== undefined) {
            this.tcpBuffer = params.tcpBuffer;
        }
        if (params.context !== undefined) {
            this.context = params.context;
        }
        if (params.port !== undefined) {
            this.port = params.port;
        }
        if (params.status !== undefined) {
            this.status = params.status;
        }
        if (params.isRunning !== undefined) {
            this.isRunning = params.isRunning;
        }
        if (params.appNames !== undefined) {
            this.appNames = params.appNames;
        }
        if (params.allAppNames !== undefined) {
            this.allAppNames = params.allAppNames;
        }
        if (params.searchText !== undefined) {
            this.searchText = params.searchText;
        }
        if (params.isConnected !== undefined) {
            this.isConnected = params.isConnected;
        }
        if (params.currentPage !== undefined) {
            this.currentPage = params.currentPage;
        }
        if (params.currentAppDetails !== undefined) {
            this.currentAppDetails = params.currentAppDetails;
        }
        if (params.selectedAppNamespace !== undefined) {
            this.selectedAppNamespace = params.selectedAppNamespace;
        }
        if (params.currentAppSurfaceJson !== undefined) {
            this.currentAppSurfaceJson = params.currentAppSurfaceJson;
        }
        if (params.parsedAppSurface !== undefined) {
            this.parsedAppSurface = params.parsedAppSurface;
        }
        if (params.detailsViewMode !== undefined) {
            this.detailsViewMode = params.detailsViewMode;
        }
        if (params.udmfContent !== undefined) {
            this.udmfContent = params.udmfContent;
        }
        if (params.udmfStatus !== undefined) {
            this.udmfStatus = params.udmfStatus;
        }
        if (params.udmfQueryUri !== undefined) {
            this.udmfQueryUri = params.udmfQueryUri;
        }
        if (params.vulnerableAbilities !== undefined) {
            this.vulnerableAbilities = params.vulnerableAbilities;
        }
        if (params.filteredVulnerableAbilities !== undefined) {
            this.filteredVulnerableAbilities = params.filteredVulnerableAbilities;
        }
        if (params.isLoadingAbilities !== undefined) {
            this.isLoadingAbilities = params.isLoadingAbilities;
        }
        if (params.selectedAbility !== undefined) {
            this.selectedAbility = params.selectedAbility;
        }
        if (params.customWantAction !== undefined) {
            this.customWantAction = params.customWantAction;
        }
        if (params.customWantEntity !== undefined) {
            this.customWantEntity = params.customWantEntity;
        }
        if (params.srv !== undefined) {
            this.srv = params.srv;
        }
        if (params.serverCli !== undefined) {
            this.serverCli = params.serverCli;
        }
        if (params.NOTIFICATION_ID !== undefined) {
            this.NOTIFICATION_ID = params.NOTIFICATION_ID;
        }
    }
    updateStateVars(params: Index_Params) {
    }
    purgeVariableDependenciesOnElmtId(rmElmtId) {
        this.__port.purgeDependencyOnElmtId(rmElmtId);
        this.__status.purgeDependencyOnElmtId(rmElmtId);
        this.__isRunning.purgeDependencyOnElmtId(rmElmtId);
        this.__appNames.purgeDependencyOnElmtId(rmElmtId);
        this.__allAppNames.purgeDependencyOnElmtId(rmElmtId);
        this.__searchText.purgeDependencyOnElmtId(rmElmtId);
        this.__isConnected.purgeDependencyOnElmtId(rmElmtId);
        this.__currentPage.purgeDependencyOnElmtId(rmElmtId);
        this.__currentAppDetails.purgeDependencyOnElmtId(rmElmtId);
        this.__selectedAppNamespace.purgeDependencyOnElmtId(rmElmtId);
        this.__currentAppSurfaceJson.purgeDependencyOnElmtId(rmElmtId);
        this.__parsedAppSurface.purgeDependencyOnElmtId(rmElmtId);
        this.__detailsViewMode.purgeDependencyOnElmtId(rmElmtId);
        this.__udmfContent.purgeDependencyOnElmtId(rmElmtId);
        this.__udmfStatus.purgeDependencyOnElmtId(rmElmtId);
        this.__udmfQueryUri.purgeDependencyOnElmtId(rmElmtId);
        this.__vulnerableAbilities.purgeDependencyOnElmtId(rmElmtId);
        this.__filteredVulnerableAbilities.purgeDependencyOnElmtId(rmElmtId);
        this.__isLoadingAbilities.purgeDependencyOnElmtId(rmElmtId);
        this.__selectedAbility.purgeDependencyOnElmtId(rmElmtId);
        this.__customWantAction.purgeDependencyOnElmtId(rmElmtId);
        this.__customWantEntity.purgeDependencyOnElmtId(rmElmtId);
    }
    aboutToBeDeleted() {
        this.__port.aboutToBeDeleted();
        this.__status.aboutToBeDeleted();
        this.__isRunning.aboutToBeDeleted();
        this.__appNames.aboutToBeDeleted();
        this.__allAppNames.aboutToBeDeleted();
        this.__searchText.aboutToBeDeleted();
        this.__isConnected.aboutToBeDeleted();
        this.__currentPage.aboutToBeDeleted();
        this.__currentAppDetails.aboutToBeDeleted();
        this.__selectedAppNamespace.aboutToBeDeleted();
        this.__currentAppSurfaceJson.aboutToBeDeleted();
        this.__parsedAppSurface.aboutToBeDeleted();
        this.__detailsViewMode.aboutToBeDeleted();
        this.__udmfContent.aboutToBeDeleted();
        this.__udmfStatus.aboutToBeDeleted();
        this.__udmfQueryUri.aboutToBeDeleted();
        this.__vulnerableAbilities.aboutToBeDeleted();
        this.__filteredVulnerableAbilities.aboutToBeDeleted();
        this.__isLoadingAbilities.aboutToBeDeleted();
        this.__selectedAbility.aboutToBeDeleted();
        this.__customWantAction.aboutToBeDeleted();
        this.__customWantEntity.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }
    private abilitiesSearchText: string;
    private tcpBuffer: string;
    private context;
    private __port: ObservedPropertySimplePU<string>;
    get port() {
        return this.__port.get();
    }
    set port(newValue: string) {
        this.__port.set(newValue);
    }
    private __status: ObservedPropertySimplePU<string>;
    get status() {
        return this.__status.get();
    }
    set status(newValue: string) {
        this.__status.set(newValue);
    }
    private __isRunning: ObservedPropertySimplePU<boolean>;
    get isRunning() {
        return this.__isRunning.get();
    }
    set isRunning(newValue: boolean) {
        this.__isRunning.set(newValue);
    }
    private __appNames: ObservedPropertyObjectPU<AppInfo[]>; // This will be the filtered list displayed
    get appNames() {
        return this.__appNames.get();
    }
    set appNames(newValue: AppInfo[]) {
        this.__appNames.set(newValue);
    }
    private __allAppNames: ObservedPropertyObjectPU<AppInfo[]>; // NEW: This will hold the full list obtained from PC
    get allAppNames() {
        return this.__allAppNames.get();
    }
    set allAppNames(newValue: AppInfo[]) {
        this.__allAppNames.set(newValue);
    }
    private __searchText: ObservedPropertySimplePU<string>; // NEW: For the search input field
    get searchText() {
        return this.__searchText.get();
    }
    set searchText(newValue: string) {
        this.__searchText.set(newValue);
    }
    private __isConnected: ObservedPropertySimplePU<boolean>; // Flag to specify if server is connected
    get isConnected() {
        return this.__isConnected.get();
    }
    set isConnected(newValue: boolean) {
        this.__isConnected.set(newValue);
    }
    private __currentPage: ObservedPropertySimplePU<'list' | 'details' | 'vulnerableAbilities' | 'abilityDetails'>;
    get currentPage() {
        return this.__currentPage.get();
    }
    set currentPage(newValue: 'list' | 'details' | 'vulnerableAbilities' | 'abilityDetails') {
        this.__currentPage.set(newValue);
    }
    private __currentAppDetails: ObservedPropertySimplePU<string>;
    get currentAppDetails() {
        return this.__currentAppDetails.get();
    }
    set currentAppDetails(newValue: string) {
        this.__currentAppDetails.set(newValue);
    }
    private __selectedAppNamespace: ObservedPropertySimplePU<string>;
    get selectedAppNamespace() {
        return this.__selectedAppNamespace.get();
    }
    set selectedAppNamespace(newValue: string) {
        this.__selectedAppNamespace.set(newValue);
    }
    private __currentAppSurfaceJson: ObservedPropertySimplePU<string>;
    get currentAppSurfaceJson() {
        return this.__currentAppSurfaceJson.get();
    }
    set currentAppSurfaceJson(newValue: string) {
        this.__currentAppSurfaceJson.set(newValue);
    }
    private __parsedAppSurface: ObservedPropertyObjectPU<AppSurfaceData | null>;
    get parsedAppSurface() {
        return this.__parsedAppSurface.get();
    }
    set parsedAppSurface(newValue: AppSurfaceData | null) {
        this.__parsedAppSurface.set(newValue);
    }
    private __detailsViewMode: ObservedPropertySimplePU<'raw' | 'parsed'>;
    get detailsViewMode() {
        return this.__detailsViewMode.get();
    }
    set detailsViewMode(newValue: 'raw' | 'parsed') {
        this.__detailsViewMode.set(newValue);
    }
    private __udmfContent: ObservedPropertyObjectPU<string[]>; // Existing UDMF content state
    get udmfContent() {
        return this.__udmfContent.get();
    }
    set udmfContent(newValue: string[]) {
        this.__udmfContent.set(newValue);
    }
    private __udmfStatus: ObservedPropertySimplePU<string>; // Existing UDMF status state
    get udmfStatus() {
        return this.__udmfStatus.get();
    }
    set udmfStatus(newValue: string) {
        this.__udmfStatus.set(newValue);
    }
    private __udmfQueryUri: ObservedPropertySimplePU<string>; // MODIFIED: Renamed and updated placeholder for UDMF
    get udmfQueryUri() {
        return this.__udmfQueryUri.get();
    }
    set udmfQueryUri(newValue: string) {
        this.__udmfQueryUri.set(newValue);
    }
    //State to get invokable abilities
    private __vulnerableAbilities: ObservedPropertyObjectPU<VulnerableAbility[]>;
    get vulnerableAbilities() {
        return this.__vulnerableAbilities.get();
    }
    set vulnerableAbilities(newValue: VulnerableAbility[]) {
        this.__vulnerableAbilities.set(newValue);
    }
    private __filteredVulnerableAbilities: ObservedPropertyObjectPU<VulnerableAbility[]>;
    get filteredVulnerableAbilities() {
        return this.__filteredVulnerableAbilities.get();
    }
    set filteredVulnerableAbilities(newValue: VulnerableAbility[]) {
        this.__filteredVulnerableAbilities.set(newValue);
    }
    private __isLoadingAbilities: ObservedPropertySimplePU<boolean>;
    get isLoadingAbilities() {
        return this.__isLoadingAbilities.get();
    }
    set isLoadingAbilities(newValue: boolean) {
        this.__isLoadingAbilities.set(newValue);
    }
    private __selectedAbility: ObservedPropertyObjectPU<VulnerableAbility | null>;
    get selectedAbility() {
        return this.__selectedAbility.get();
    }
    set selectedAbility(newValue: VulnerableAbility | null) {
        this.__selectedAbility.set(newValue);
    }
    private __customWantAction: ObservedPropertySimplePU<string>;
    get customWantAction() {
        return this.__customWantAction.get();
    }
    set customWantAction(newValue: string) {
        this.__customWantAction.set(newValue);
    }
    private __customWantEntity: ObservedPropertySimplePU<string>;
    get customWantEntity() {
        return this.__customWantEntity.get();
    }
    set customWantEntity(newValue: string) {
        this.__customWantEntity.set(newValue);
    }
    // TCP Server specific states, now directly in UIAbility
    private srv?: socket.TCPSocketServer;
    private serverCli: socket.TCPSocketConnection | undefined;
    private readonly NOTIFICATION_ID: number; // Unique ID for the foreground service notification
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
                    {
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
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Failed to get WantAgent for UIAbility: ${JSON.stringify(e)}`);
                this.status = `WantAgent Error: ${(e as BusinessError).code}`;
                this.isRunning = false;
                // Ensure notification is cancelled if WantAgent cannot be obtained
                notificationManager.cancel(this.NOTIFICATION_ID);
                return;
            }
            // Promote UIAbility to foreground service using the correct signature
            backgroundTaskManager.startBackgroundRunning(this.context, backgroundTaskManager.BackgroundMode.DATA_TRANSFER, // Example BackgroundMode enum
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
        }
        catch (e) {
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
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Error closing client connection: ${JSON.stringify(e)}`);
            }
            finally {
                this.serverCli = undefined;
            }
        }
        if (this.srv) {
            try {
                this.srv.off('connect');
                // No srv.close() as it causes issues. Rely on garbage collection/process termination.
                hilog.info(0x0000, 'AppLog', 'Server connect listener removed.');
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Error removing server listener: ${JSON.stringify(e)}`);
            }
            finally {
                this.srv = undefined;
            }
        }
        // Stop foreground running
        try {
            await backgroundTaskManager.stopBackgroundRunning(this.context); // Re-enabled stopBackgroundRunning
            hilog.info(0x0000, 'AppLog', 'UIAbility stopped foreground running.');
        }
        catch (e) {
            hilog.error(0x0000, 'AppLog', `Failed to stop background running: ${JSON.stringify(e)}`);
        }
        // Cancel the notification
        try {
            await notificationManager.cancel(this.NOTIFICATION_ID);
            hilog.info(0x0000, 'AppLog', `Notification ${this.NOTIFICATION_ID} cancelled.`);
        }
        catch (e) {
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
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Error closing client connection: ${JSON.stringify(e)}`);
            }
            finally {
                this.serverCli = undefined;
            }
        }
        if (this.srv) {
            try {
                this.srv.off('connect');
                hilog.info(0x0000, 'AppLog', 'Server connect listener removed.');
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Error removing server listener: ${JSON.stringify(e)}`);
            }
            finally {
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
            this.resetQueryState();
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
            }
            catch (e) {
                const errorMsg = `Failed to parse app surface JSON: ${JSON.stringify(e)}`;
                hilog.error(0x0000, 'AppLog', errorMsg);
                this.currentAppDetails = `Error processing app surface: ${errorMsg}. Received: ${jsonOutput.substring(0, Math.min(jsonOutput.length, 200))}...`;
                this.status = `App surface parse error.`;
                this.currentPage = 'details';
                this.detailsViewMode = 'raw';
                this.resetQueryState();
            }
        }
        else if (txt.startsWith('HDC_OUTPUT_ERROR:')) {
            const errorOutput = txt.substring('HDC_OUTPUT_ERROR:'.length);
            this.status = `PC reported error: ${errorOutput.substring(0, Math.min(errorOutput.length, 50))}...`;
            this.currentAppDetails = `Error from PC: ${errorOutput}`;
            this.currentPage = 'details';
            this.detailsViewMode = 'raw';
            this.resetQueryState();
        }
        else if (txt.trim().startsWith('HDC_OUTPUT_EXPOSED_ABILITIES:')) {
            const jsonAbilities = txt.substring('HDC_OUTPUT_EXPOSED_ABILITIES:'.length).trim();
            try {
                const abilities: VulnerableAbility[] = JSON.parse(jsonAbilities);
                this.vulnerableAbilities = abilities;
                this.filteredVulnerableAbilities = this.vulnerableAbilities;
                this.currentPage = 'vulnerableAbilities';
                this.status = `Received ${this.vulnerableAbilities.length} abilities.`;
                this.isLoadingAbilities = false;
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Failed to parse exposed abilities: ${JSON.stringify(e)}`);
                this.status = `Error parsing abilities: ${JSON.stringify(e)}`;
            }
        }
        else if (txt.startsWith('COMMAND_REQUEST:')) {
            const commandPayload = txt.substring('COMMAND_REQUEST:'.length).trim();
            hilog.info(0x0000, 'AppLog', `Received COMMAND_REQUEST: ${commandPayload}`);
            if (commandPayload.startsWith('udmf_query_single_app')) {
                const parts = commandPayload.split(' ');
                if (parts.length >= 2) {
                    const namespace = parts[1];
                    const groupId = parts.length === 3 ? parts[2] : 'flag'; // Default to 'flag'
                    this.handleSingleAppUDMFQuery(namespace, groupId);
                }
                else {
                    this.sendToPcClient('HDC_OUTPUT_ERROR:Invalid udmf_query_single_app command format.');
                }
            }
            else if (commandPayload.startsWith('udmf_query_all_apps')) {
                const parts = commandPayload.split(' ');
                const groupId = parts.length === 2 ? parts[1] : 'flag'; // Default to 'flag'
                this.handleAllAppsUDMFQuery(groupId);
            }
            else if (commandPayload.startsWith('apps_visible_abilities')) {
                const parts = commandPayload.split(' ');
                const sendToApp = parts.includes('-a');
                if (sendToApp) {
                    this.sendToPcClient('COMMAND_REQUEST:apps_visible_abilities -a');
                }
            }
            else if (commandPayload.startsWith('app_exec')) {
                const command = commandPayload.substring('app_exec'.length).trim();
                hilog.info(0x0000, 'AppLog', `Trying to exec ${command}`);
                this.handleAppExecCommand(command);
            }
            else if (commandPayload.startsWith('shell_exec')) {
                const command = commandPayload.substring('shell_exec'.length).trim();
                hilog.info(0x0000, 'AppLog', `Trying to shell_exec ${command}`);
                this.handleShellExecCommand(command);
            }
        }
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
        }
        catch (e) {
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
    private resetQueryState(): void {
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
        }
        else {
            const lowerCaseSearchText = this.searchText.toLowerCase();
            this.appNames = this.allAppNames.filter(app => app.name.toLowerCase().includes(lowerCaseSearchText) ||
                app.bundleName.toLowerCase().includes(lowerCaseSearchText));
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
        }
        catch (e) {
            const errorMsg = `Failed to invoke ability ${abilityName}: ${JSON.stringify(e)}`;
            hilog.error(0x0000, 'AppLog', errorMsg);
            this.status = `Invoke failed: ${errorMsg}`;
        }
    }
    private async onInvokeAbilityWithWant(app: string, ability: string, action: string, entity: string): Promise<void> {
        this.status = `Invoking ability ${ability} with Want...`;
        // Construimos el comando con el formato esperado
        const commandToSend = `COMMAND_REQUEST:invoke_with_want app=${app} ability=${ability} action=${action} entity=${entity}`;
        try {
            const result = await this.sendToPcClient(commandToSend);
            if (result.startsWith('ERROR')) {
                this.status = `Error invoking ability: ${result.substring('ERROR:'.length)}`;
            }
            else {
                this.status = `Invoke with Want sent successfully: ${result}`;
            }
        }
        catch (e) {
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
        const dataList: unifiedDataChannel.UnifiedData[] = await new Promise<unifiedDataChannel.UnifiedData[]>((resolve, reject) => {
            unifiedDataChannel.queryData(options, (err: BusinessError | null, data: unifiedDataChannel.UnifiedData[]) => {
                if (err) {
                    hilog.error(0x0000, 'UDMFService', `Error querying UDMF for key ${udmfFullUri} in Promise wrapper: Code: %{public}s, Message: %{public}s, Name: %{public}s, Stack: %{public}s`, err.code, err.message, err.name, err.stack);
                    reject(err); // Reject the promise on error
                }
                else {
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
                        }
                        else {
                            hilog.info(0x0000, 'UDMFService', `PlainText content for key ${udmfFullUri}, record ${j} was empty.`);
                        }
                    }
                }
            }
            hilog.info(0x0000, 'UDMFService', `Finished querying UDMF for key ${udmfFullUri}. Found ${foundContents.length} items.`);
        }
        else {
            hilog.info(0x0000, 'UDMFService', `No data list returned for key: ${udmfFullUri}.`);
        }
        return foundContents; // Always return foundContents array on success
    }
    /**
     * Handler for the "Query UDMF Content" button click.
     * Uses the value from the `udmfQueryUri` input field to perform the UDMF query.
     */
    private async onQueryUDMFTap(): Promise<void> {
        this.udmfContent = [];
        this.udmfStatus = 'Querying UDMF...';
        hilog.info(0x0000, 'AppLog', `Querying UDMF for URI from input: ${this.udmfQueryUri}`);
        try {
            const results: string[] = await this.queryUDMFContent(this.udmfQueryUri); // Use udmfQueryUri directly
            if (results.length > 0) {
                this.udmfContent = results;
                this.udmfStatus = `Found ${results.length} UDMF records.`;
            }
            else {
                this.udmfStatus = 'No UDMF content found for this URI.';
            }
            hilog.info(0x0000, 'AppLog', `UDMF query complete. Status: ${this.udmfStatus}`);
        }
        catch (e) {
            const errorMsg = `UDMF Query Failed: ${JSON.stringify(e)}`;
            this.udmfStatus = errorMsg;
            hilog.error(0x0000, 'AppLog', errorMsg);
        }
    }
    private async handleSingleAppUDMFQuery(namespace: string, groupId: string): Promise<void> {
        hilog.info(0x0000, 'AppLog', `Handling single app UDMF query for ${namespace} with group ID ${groupId}`);
        const udmfUri = `udmf://DataHub/${namespace}/${groupId}`;
        try {
            const content = await this.queryUDMFContent(udmfUri);
            const resultPayload: UDMFQueryResult = {
                uri: udmfUri,
                content: content
            };
            this.sendToPcClient(`UDMF_QUERY_RESULT:${JSON.stringify(resultPayload)}`);
        }
        catch (e) {
            const errorMsg = `Failed to query UDMF for ${namespace}: ${JSON.stringify(e)}`;
            hilog.error(0x0000, 'AppLog', errorMsg);
            this.sendToPcClient(`HDC_OUTPUT_ERROR:${errorMsg}`);
        }
    }
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
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Error querying UDMF for app ${app.bundleName}: ${JSON.stringify(e)}`);
                // Continue to next app even if one fails
            }
        }
        this.sendToPcClient(`UDMF_APPS_WITH_CONTENT:${JSON.stringify(appsWithContent)}`);
    }
    private async handleAppExecCommand(command: string): Promise<void> {
        hilog.info(0x0000, 'AppLog', `Executing command: ${command}`);
        let output: string = '';
        try {
            if (typeof executeCommand === 'undefined' || typeof executeCommand !== 'function') {
                hilog.error(0x0000, 'AppLog', `Native executeCommand function is not available.`);
                return;
            }
            const parts = command.split(' ');
            const binaryToExecute = parts[0];
            const commandArguments = parts.slice(1).join(' ');
            hilog.info(0x0000, 'AppLog', `Attempting to execute: ${command}`);
            output = executeCommand(binaryToExecute, commandArguments);
            hilog.info(0x0000, 'AppLog', `Command output: ${output}`);
        }
        catch (e) {
            const error: Error = e as Error;
            hilog.error(0x0000, 'AppLog', `Command execution failed: %{public}s`, error.message);
            output = `[ERROR] Failed to execute command: ${command}\nError: ${JSON.stringify(e)}`;
        }
        this.sendToPcClient(`EXEC_RESULT: ${output}`);
    }
    private async handleShellExecCommand(command: string): Promise<void> {
        hilog.info(0x0000, 'AppLog', `Executing command: ${command}`);
        let output: string = '';
        try {
            if (typeof executeCommand === 'undefined' || typeof executeCommand !== 'function') {
                hilog.error(0x0000, 'AppLog', `Native executeCommand function is not available.`);
                return;
            }
            hilog.info(0x0000, 'AppLog', `Attempting to execute: ${command}`);
            output = processShellCommand(command);
            hilog.info(0x0000, 'AppLog', `Command output: ${output}`);
        }
        catch (e) {
            const error: Error = e as Error;
            hilog.error(0x0000, 'AppLog', `Command execution failed: %{public}s`, error.message);
            output = `[ERROR] Failed to execute shell command: ${command}\nError: ${JSON.stringify(e)}`;
        }
        this.sendToPcClient(`EXEC_RESULT: ${output}`);
    }
    onBackToList(): void {
        this.currentPage = 'list';
        this.resetDetailsState();
        this.resetQueryState();
        this.status = 'Ready for app list.';
    }
    private filterAbilities() {
        if (this.abilitiesSearchText === '') {
            // Si el cuadro de búsqueda está vacío, muestra la lista completa.
            this.filteredVulnerableAbilities = this.vulnerableAbilities;
        }
        else {
            // Si hay texto, filtra la lista completa.
            // El método `toLowerCase()` se usa para hacer la búsqueda insensible a mayúsculas.
            const lowerCaseSearchText = this.abilitiesSearchText.toLowerCase();
            this.filteredVulnerableAbilities = this.vulnerableAbilities.filter(ability => 
            // Filtra por el nombre de la habilidad o el nombre de la app.
            ability.ability.toLowerCase().includes(lowerCaseSearchText) ||
                ability.app.toLowerCase().includes(lowerCaseSearchText));
        }
    }
    private async createSandboxFile(fileName: string, fileContent: string): Promise<void> {
        hilog.info(0x0000, 'WebViewAbility', 'onWindowStageCreate: Starting WebViewAbility.');
        // Use an immediately invoked async function to handle asynchronous file operations
        (async () => {
            let context: common.Context = this.context; // `this.context` is already the AbilityContext here
            // Get the application's internal files directory (sandbox)
            const filesDir = await context.filesDir;
            const fullPath = `${filesDir}/${fileName}`;
            const localFilePath = `file://${fullPath}`; // Store the file:// URI
            hilog.info(0x0000, 'AppLog', `Attempting to create file at: ${fullPath}`);
            try {
                // Corrected: Explicitly type 'file' as fileio.File, as it represents the file object.
                // Subsequent operations use file.fd (file descriptor).
                const file: fileIo.File = fileIo.openSync(fullPath, fileIo.OpenMode.CREATE | fileIo.OpenMode.WRITE_ONLY);
                fileIo.writeSync(file.fd, fileContent); // Use file.fd for writeSync
                fileIo.fsyncSync(file.fd); // Use file.fd for fsyncSync to ensure data is flushed
                fileIo.closeSync(file.fd); // Use file.fd for closeSync
                hilog.info(0x0000, 'AppLog', `Successfully created local file: ${fullPath}`);
                hilog.info(0x0000, 'AppLog', `Local file URI to test: ${localFilePath}`);
            }
            catch (e) {
                hilog.error(0x0000, 'AppLog', `Failed to create local file: Code: ${e.code}, Message: ${e.message}`);
                // Consider updating a global state or log for WebViewPage to show this error
            }
        })();
    }
    initialRender() {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.width('100%');
            Column.height('100%');
            Column.justifyContent(FlexAlign.Start);
        }, Column);
        {
            this.observeComponentCreation2((elmtId, isInitialRender) => {
                if (isInitialRender) {
                    let componentCall = new 
                    // App Header
                    Harm0nyz3rHeader(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 853, col: 7 });
                    ViewPU.create(componentCall);
                    let paramsLambda = () => {
                        return {};
                    };
                    componentCall.paramsGenerator_ = paramsLambda;
                }
                else {
                    this.updateStateVarsOfChildByElmtId(elmtId, {});
                }
            }, { name: "Harm0nyz3rHeader" });
        }
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            // Server controls and status section
            Column.create({ space: 8 });
            // Server controls and status section
            Column.width('100%');
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            // Port input and Start/Stop buttons
            Row.create({ space: 8 });
            // Port input and Start/Stop buttons
            Row.width('100%');
            // Port input and Start/Stop buttons
            Row.padding({ left: 16, right: 16 });
        }, Row);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create('TCP port:');
            Text.fontSize(16);
        }, Text);
        Text.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            TextInput.create({ text: this.port, placeholder: '51337' });
            TextInput.type(InputType.Number);
            TextInput.width(80);
            TextInput.onChange(v => this.port = v);
        }, TextInput);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Button.createWithLabel('Start Server');
            Button.layoutWeight(1);
            Button.onClick(() => this.startServer());
        }, Button);
        Button.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Button.createWithLabel('Stop Server');
            Button.layoutWeight(1);
            Button.onClick(() => this.stopServer());
        }, Button);
        Button.pop();
        // Port input and Start/Stop buttons
        Row.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            // Server status indicator and text
            Row.create({ space: 8 });
            // Server status indicator and text
            Row.padding({ left: 16, right: 16, bottom: 8 });
        }, Row);
        {
            this.observeComponentCreation2((elmtId, isInitialRender) => {
                if (isInitialRender) {
                    let componentCall = new IndicatorCircle(this, { status: this.isRunning }, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 877, col: 11 });
                    ViewPU.create(componentCall);
                    let paramsLambda = () => {
                        return {
                            status: this.isRunning
                        };
                    };
                    componentCall.paramsGenerator_ = paramsLambda;
                }
                else {
                    this.updateStateVarsOfChildByElmtId(elmtId, {
                        status: this.isRunning
                    });
                }
            }, { name: "IndicatorCircle" });
        }
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(`Status: ${this.status}`);
            Text.fontSize(14);
        }, Text);
        Text.pop();
        // Server status indicator and text
        Row.pop();
        // Server controls and status section
        Column.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Divider.create();
            Divider.margin({ top: 16, bottom: 16 });
        }, Divider);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            // 3. Main Content Area (Conditional Rendering using standard if/else if)
            if (this.currentPage === 'list') {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Row.create();
                    }, Row);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Shell');
                        Button.backgroundColor(Color.Black);
                        Button.fontColor(Color.White);
                        Button.onClick(() => {
                            router.pushUrl({ url: 'pages/CommandExecutionPage' });
                        });
                    }, Button);
                    Button.pop();
                    Column.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Blank.create();
                        Blank.width('5%');
                    }, Blank);
                    Blank.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Get App List from PC');
                        Button.backgroundColor(Color.Blue);
                        Button.fontColor(Color.White);
                        Button.margin({ bottom: 10 });
                        Button.onClick(() => this.requestAppListFromPC());
                    }, Button);
                    Button.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Button to get a list with all callable abilities (those that we're able to open without privileges)
                        Button.createWithLabel('Get abilities from PC');
                        // Button to get a list with all callable abilities (those that we're able to open without privileges)
                        Button.backgroundColor(Color.Green);
                        // Button to get a list with all callable abilities (those that we're able to open without privileges)
                        Button.fontColor(Color.White);
                        // Button to get a list with all callable abilities (those that we're able to open without privileges)
                        Button.margin({ bottom: 10 });
                        // Button to get a list with all callable abilities (those that we're able to open without privileges)
                        Button.onClick(() => {
                            // Due to slowness of request innecessary interactions with server are skipped
                            if (this.vulnerableAbilities.length === 0) {
                                // No data, send request to server
                                this.isLoadingAbilities = true;
                                this.sendToPcClient('COMMAND_REQUEST:apps_visible_abilities -a');
                                this.status = 'Requesting invocable abilities from PC...';
                            }
                            else {
                                // Already saved data, skip server request
                                this.status = 'Using cached invocable abilities.';
                            }
                            if (this.isConnected) {
                                this.currentPage = 'vulnerableAbilities';
                            }
                            else {
                                this.status = 'You are not connected to PC.';
                            }
                        });
                    }, Button);
                    // Button to get a list with all callable abilities (those that we're able to open without privileges)
                    Button.pop();
                    Column.pop();
                    Row.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // NEW: Search input for app list
                        TextInput.create({ text: this.searchText, placeholder: 'Search apps...' });
                        // NEW: Search input for app list
                        TextInput.placeholderColor(Color.Gray);
                        // NEW: Search input for app list
                        TextInput.placeholderFont({ size: 14 });
                        // NEW: Search input for app list
                        TextInput.backgroundColor(0xFFF8F8F8);
                        // NEW: Search input for app list
                        TextInput.borderRadius(8);
                        // NEW: Search input for app list
                        TextInput.padding({ left: 10, right: 10, top: 8, bottom: 8 });
                        // NEW: Search input for app list
                        TextInput.margin({ bottom: 10, left: 16, right: 16 });
                        // NEW: Search input for app list
                        TextInput.onChange(v => {
                            this.searchText = v;
                            this.filterApps(); // Filter the list as user types
                        });
                    }, TextInput);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Text.create('Installed Applications:');
                        Text.fontSize(16);
                        Text.fontWeight(FontWeight.Bold);
                        Text.margin({ left: 16, right: 16 });
                    }, Text);
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Scroll.create();
                        Scroll.width('90%');
                        Scroll.height('400vp');
                        Scroll.backgroundColor(0xFFF0F0F0);
                        Scroll.border({ width: 1, color: Color.Gray, radius: 8 });
                        Scroll.borderRadius(8);
                    }, Scroll);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                        Column.width('100%');
                        Column.padding({ left: 8, right: 8 });
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        If.create();
                        if (this.appNames.length === 0 && this.allAppNames.length > 0) { // MODIFIED: Added check for allAppNames
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Text.create('No applications found matching your search criteria.');
                                    Text.fontSize(12);
                                    Text.fontColor(Color.Gray);
                                    Text.padding(8);
                                    Text.textAlign(TextAlign.Center);
                                }, Text);
                                Text.pop();
                            });
                        }
                        else if (this.appNames.length === 0) {
                            this.ifElseBranchUpdateFunction(1, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Text.create('No applications loaded. Connect to PC and use "Get App List from PC" button or "list_apps -a" in the console.');
                                    Text.fontSize(12);
                                    Text.fontColor(Color.Gray);
                                    Text.padding(8);
                                    Text.textAlign(TextAlign.Center);
                                }, Text);
                                Text.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(2, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    ForEach.create();
                                    const forEachItemGenFunction = _item => {
                                        const app = _item;
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Row.create();
                                            Row.width('100%');
                                            Row.padding(4);
                                            Row.margin({ bottom: 4 });
                                            Row.backgroundColor(0xFFE0E0E0);
                                            Row.borderRadius(8);
                                        }, Row);
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Text.create(app.name);
                                            Text.layoutWeight(1);
                                            Text.fontSize(16);
                                            Text.padding({ left: 8 });
                                        }, Text);
                                        Text.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Button.createWithLabel('Info');
                                            Button.width(60);
                                            Button.height(30);
                                            Button.borderRadius(15);
                                            Button.backgroundColor(Color.Brown);
                                            Button.fontColor(Color.White);
                                            Button.margin({ right: 4 });
                                            Button.onClick(() => this.onAppSurfaceTap(app.bundleName));
                                        }, Button);
                                        Button.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Button.createWithLabel('Raw');
                                            Button.width(60);
                                            Button.height(30);
                                            Button.borderRadius(15);
                                            Button.backgroundColor(Color.Orange);
                                            Button.fontColor(Color.White);
                                            Button.onClick(() => this.onRawDetailsTap(app.bundleName));
                                        }, Button);
                                        Button.pop();
                                        Row.pop();
                                    };
                                    this.forEachUpdateFunction(elmtId, this.appNames, forEachItemGenFunction);
                                }, ForEach);
                                ForEach.pop();
                            });
                        }
                    }, If);
                    If.pop();
                    Column.pop();
                    Scroll.pop();
                    Column.pop();
                });
            }
            else if (this.currentPage === 'vulnerableAbilities') {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                        Column.padding(16);
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Row.create();
                    }, Row);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        __Common__.create();
                        __Common__.onClick(() => this.currentPage = 'list');
                    }, __Common__);
                    {
                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                            if (isInitialRender) {
                                let componentCall = new 
                                // Back to main view
                                BackButton(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 1021, col: 13 });
                                ViewPU.create(componentCall);
                                let paramsLambda = () => {
                                    return {};
                                };
                                componentCall.paramsGenerator_ = paramsLambda;
                            }
                            else {
                                this.updateStateVarsOfChildByElmtId(elmtId, {});
                            }
                        }, { name: "BackButton" });
                    }
                    __Common__.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Blank.create();
                        Blank.width(12);
                    }, Blank);
                    Blank.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        __Common__.create();
                        __Common__.onClick(() => {
                            // Clean up list and send request
                            if (this.isConnected) {
                                this.isLoadingAbilities = true;
                                this.vulnerableAbilities = [];
                                this.filteredVulnerableAbilities = [];
                                this.sendToPcClient('COMMAND_REQUEST:apps_visible_abilities -a');
                                this.status = 'Refreshing invocable abilities from PC...';
                            }
                            else {
                                this.status = 'You are not connected to PC.';
                            }
                        });
                    }, __Common__);
                    {
                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                            if (isInitialRender) {
                                let componentCall = new 
                                // Refresh abilities list
                                RefreshButton(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 1026, col: 13 });
                                ViewPU.create(componentCall);
                                let paramsLambda = () => {
                                    return {};
                                };
                                componentCall.paramsGenerator_ = paramsLambda;
                            }
                            else {
                                this.updateStateVarsOfChildByElmtId(elmtId, {});
                            }
                        }, { name: "RefreshButton" });
                    }
                    __Common__.pop();
                    Row.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Title
                        Text.create('Invocable Abilities');
                        // Title
                        Text.fontSize(20);
                        // Title
                        Text.fontWeight(FontWeight.Bold);
                        // Title
                        Text.margin({ top: 16, bottom: 16 });
                    }, Text);
                    // Title
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        TextInput.create({ text: this.searchText, placeholder: 'Search apps...' });
                        TextInput.placeholderColor(Color.Gray);
                        TextInput.placeholderFont({ size: 14 });
                        TextInput.backgroundColor(0xFFF8F8F8);
                        TextInput.borderRadius(8);
                        TextInput.padding({ left: 10, right: 10, top: 8, bottom: 8 });
                        TextInput.margin({ bottom: 10, left: 16, right: 16 });
                        TextInput.onChange((value: string) => {
                            this.abilitiesSearchText = value;
                            this.filterAbilities(); // Filter the list as user types
                        });
                    }, TextInput);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        If.create();
                        if (this.isLoadingAbilities) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Row.create();
                                    Row.margin({ bottom: 16 });
                                }, Row);
                                {
                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                        if (isInitialRender) {
                                            let componentCall = new LoadingIcon(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 1062, col: 15 });
                                            ViewPU.create(componentCall);
                                            let paramsLambda = () => {
                                                return {};
                                            };
                                            componentCall.paramsGenerator_ = paramsLambda;
                                        }
                                        else {
                                            this.updateStateVarsOfChildByElmtId(elmtId, {});
                                        }
                                    }, { name: "LoadingIcon" });
                                }
                                Row.pop();
                            });
                        }
                        // List
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // List
                        Scroll.create();
                        // List
                        Scroll.height('55%');
                    }, Scroll);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        ForEach.create();
                        const forEachItemGenFunction = _item => {
                            const ability = _item;
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Row.create();
                                Row.padding(12);
                                Row.margin({ bottom: 10 });
                                Row.backgroundColor(0xFFF5F5F5);
                                Row.borderRadius(8);
                            }, Row);
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Column.create();
                                Column.layoutWeight(1);
                            }, Column);
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Text.create(ability.ability);
                                Text.fontSize(16);
                                Text.fontWeight(FontWeight.Medium);
                            }, Text);
                            Text.pop();
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Text.create(ability.app);
                                Text.fontSize(12);
                                Text.fontColor(Color.Gray);
                            }, Text);
                            Text.pop();
                            Column.pop();
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                __Common__.create();
                                __Common__.onClick(() => {
                                    this.selectedAbility = ability;
                                    this.currentPage = 'abilityDetails';
                                });
                            }, __Common__);
                            {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    if (isInitialRender) {
                                        let componentCall = new InfoButton(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 1082, col: 19 });
                                        ViewPU.create(componentCall);
                                        let paramsLambda = () => {
                                            return {};
                                        };
                                        componentCall.paramsGenerator_ = paramsLambda;
                                    }
                                    else {
                                        this.updateStateVarsOfChildByElmtId(elmtId, {});
                                    }
                                }, { name: "InfoButton" });
                            }
                            __Common__.pop();
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                __Common__.create();
                                __Common__.onClick(() => this.onInvokeAbility(ability.app, ability.ability));
                            }, __Common__);
                            {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    if (isInitialRender) {
                                        let componentCall = new InvokeButton(this, {}, undefined, elmtId, () => { }, { page: "entry/src/main/ets/pages/Index.ets", line: 1088, col: 19 });
                                        ViewPU.create(componentCall);
                                        let paramsLambda = () => {
                                            return {};
                                        };
                                        componentCall.paramsGenerator_ = paramsLambda;
                                    }
                                    else {
                                        this.updateStateVarsOfChildByElmtId(elmtId, {});
                                    }
                                }, { name: "InvokeButton" });
                            }
                            __Common__.pop();
                            Row.pop();
                        };
                        this.forEachUpdateFunction(elmtId, this.filteredVulnerableAbilities, forEachItemGenFunction);
                    }, ForEach);
                    ForEach.pop();
                    Column.pop();
                    // List
                    Scroll.pop();
                    Column.pop();
                });
            }
            else if (this.currentPage === 'details') {
                this.ifElseBranchUpdateFunction(2, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Back to App List');
                        Button.onClick(() => this.onBackToList());
                        Button.margin({ bottom: 10 });
                    }, Button);
                    Button.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Text.create(`Details for: ${this.selectedAppNamespace}`);
                        Text.fontSize(18);
                        Text.fontWeight(FontWeight.Medium);
                        Text.margin({ bottom: 5 });
                    }, Text);
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Row.create({ space: 8 });
                        Row.margin({ bottom: 10 });
                    }, Row);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Show Raw Dump');
                        Button.backgroundColor(this.detailsViewMode === 'raw' ? Color.Blue : Color.Gray);
                        Button.fontColor(Color.White);
                        Button.onClick(() => this.detailsViewMode = 'raw');
                    }, Button);
                    Button.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Show Parsed Info');
                        Button.backgroundColor(this.detailsViewMode === 'parsed' ? Color.Blue : Color.Gray);
                        Button.fontColor(Color.White);
                        Button.onClick(() => this.detailsViewMode = 'parsed');
                    }, Button);
                    Button.pop();
                    Row.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Scroll.create();
                        Scroll.width('90%');
                        Scroll.height('400vp');
                        Scroll.backgroundColor(0xFFF0F0F0);
                        Scroll.border({ width: 1, color: Color.Gray, radius: 8 });
                        Scroll.borderRadius(8);
                    }, Scroll);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        If.create();
                        if (this.detailsViewMode === 'raw') {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Text.create(this.currentAppDetails);
                                    Text.fontSize(16);
                                    Text.padding(10);
                                    Text.backgroundColor(0xFFF0F0F0);
                                    Text.borderRadius(5);
                                    Text.width('100%');
                                    Text.textAlign(TextAlign.Start);
                                }, Text);
                                Text.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    If.create();
                                    if (this.parsedAppSurface) {
                                        this.ifElseBranchUpdateFunction(0, () => {
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Column.create();
                                                Column.alignItems(HorizontalAlign.Start);
                                                Column.width('100%');
                                                Column.padding(10);
                                            }, Column);
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create(`App Name: ${this.parsedAppSurface.bundleName}`);
                                                Text.fontSize(20);
                                                Text.fontWeight(FontWeight.Bold);
                                                Text.margin({ bottom: 8 });
                                            }, Text);
                                            Text.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create(`Debug Mode: ${this.parsedAppSurface.debugMode ? 'Yes' : 'No'}`);
                                                Text.fontSize(16);
                                            }, Text);
                                            Text.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create(`System App: ${this.parsedAppSurface.systemApp ? 'Yes' : 'No'}`);
                                                Text.fontSize(16);
                                                Text.margin({ bottom: 16 });
                                            }, Text);
                                            Text.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                If.create();
                                                if (this.parsedAppSurface.requiredAppPermissions && this.parsedAppSurface.requiredAppPermissions.length > 0) {
                                                    this.ifElseBranchUpdateFunction(0, () => {
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Text.create('Overall Required Permissions:');
                                                            Text.fontSize(18);
                                                            Text.fontWeight(FontWeight.Bold);
                                                            Text.margin({ bottom: 8 });
                                                        }, Text);
                                                        Text.pop();
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            ForEach.create();
                                                            const forEachItemGenFunction = _item => {
                                                                const perm = _item;
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Text.create(`- ${perm}`);
                                                                    Text.fontSize(14);
                                                                    Text.fontColor(Color.Black);
                                                                }, Text);
                                                                Text.pop();
                                                            };
                                                            this.forEachUpdateFunction(elmtId, this.parsedAppSurface.requiredAppPermissions, forEachItemGenFunction);
                                                        }, ForEach);
                                                        ForEach.pop();
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Divider.create();
                                                            Divider.margin({ top: 16, bottom: 16 });
                                                        }, Divider);
                                                    });
                                                }
                                                // NEW: Query UDMF URI input field
                                                else {
                                                    this.ifElseBranchUpdateFunction(1, () => {
                                                    });
                                                }
                                            }, If);
                                            If.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                // NEW: Query UDMF URI input field
                                                Row.create({ space: 8 });
                                                // NEW: Query UDMF URI input field
                                                Row.margin({ bottom: 10 });
                                            }, Row);
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create('Query URI:');
                                                Text.fontSize(16);
                                            }, Text);
                                            Text.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                TextInput.create({ text: this.udmfQueryUri, placeholder: 'udmf://DataHub/bundle/path' });
                                                TextInput.placeholderColor(Color.Gray);
                                                TextInput.placeholderFont({ size: 14 });
                                                TextInput.backgroundColor(0xFFF8F8F8);
                                                TextInput.borderRadius(8);
                                                TextInput.padding({ left: 10, right: 10, top: 8, bottom: 8 });
                                                TextInput.layoutWeight(1);
                                                TextInput.onChange(v => this.udmfQueryUri = v);
                                            }, TextInput);
                                            // NEW: Query UDMF URI input field
                                            Row.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Button.createWithLabel('Query UDMF Content');
                                                Button.backgroundColor(Color.Green);
                                                Button.fontColor(Color.White);
                                                Button.margin({ bottom: 10 });
                                                Button.onClick(() => this.onQueryUDMFTap());
                                            }, Button);
                                            Button.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                If.create();
                                                if (this.udmfStatus) {
                                                    this.ifElseBranchUpdateFunction(0, () => {
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Text.create(`UDMF Status: ${this.udmfStatus}`);
                                                            Text.fontSize(14);
                                                            Text.fontColor(this.udmfStatus.includes('Error') ? Color.Red : Color.Black);
                                                            Text.margin({ bottom: 8 });
                                                        }, Text);
                                                        Text.pop();
                                                    });
                                                }
                                                else {
                                                    this.ifElseBranchUpdateFunction(1, () => {
                                                    });
                                                }
                                            }, If);
                                            If.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                If.create();
                                                if (this.udmfContent.length > 0) {
                                                    this.ifElseBranchUpdateFunction(0, () => {
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Text.create('UDMF Content Found:');
                                                            Text.fontSize(16);
                                                            Text.fontWeight(FontWeight.Bold);
                                                            Text.margin({ bottom: 8 });
                                                        }, Text);
                                                        Text.pop();
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            ForEach.create();
                                                            const forEachItemGenFunction = (_item, index: number) => {
                                                                const content = _item;
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Text.create(`${index + 1}. ${content}`);
                                                                    Text.fontSize(14);
                                                                    Text.fontColor(Color.Gray);
                                                                    Text.margin({ bottom: 4 });
                                                                }, Text);
                                                                Text.pop();
                                                            };
                                                            this.forEachUpdateFunction(elmtId, this.udmfContent, forEachItemGenFunction, undefined, true, false);
                                                        }, ForEach);
                                                        ForEach.pop();
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Divider.create();
                                                            Divider.margin({ top: 16, bottom: 16 });
                                                        }, Divider);
                                                    });
                                                }
                                                else {
                                                    this.ifElseBranchUpdateFunction(1, () => {
                                                    });
                                                }
                                            }, If);
                                            If.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create('Exposed Components:');
                                                Text.fontSize(18);
                                                Text.fontWeight(FontWeight.Bold);
                                                Text.margin({ bottom: 8 });
                                            }, Text);
                                            Text.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                If.create();
                                                if (this.parsedAppSurface.exposedComponents.length === 0) {
                                                    this.ifElseBranchUpdateFunction(0, () => {
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            Text.create('No exposed abilities or extensions found.');
                                                            Text.fontSize(14);
                                                            Text.fontColor(Color.Gray);
                                                        }, Text);
                                                        Text.pop();
                                                    });
                                                }
                                                else {
                                                    this.ifElseBranchUpdateFunction(1, () => {
                                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                            ForEach.create();
                                                            const forEachItemGenFunction = _item => {
                                                                const component = _item;
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Column.create();
                                                                    Column.alignItems(HorizontalAlign.Start);
                                                                    Column.width('100%');
                                                                    Column.padding(8);
                                                                    Column.margin({ bottom: 8 });
                                                                    Column.backgroundColor(0xFFE0E0E0);
                                                                    Column.borderRadius(8);
                                                                }, Column);
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Row.create();
                                                                    Row.width('100%');
                                                                    Row.margin({ bottom: 4 });
                                                                }, Row);
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Text.create(`Name: ${component.name}`);
                                                                    Text.layoutWeight(1);
                                                                    Text.fontSize(16);
                                                                    Text.fontWeight(FontWeight.Medium);
                                                                }, Text);
                                                                Text.pop();
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    If.create();
                                                                    if (component.type.includes('Ability') && component.visible) {
                                                                        this.ifElseBranchUpdateFunction(0, () => {
                                                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                Button.createWithLabel('Invoke');
                                                                                Button.width(80);
                                                                                Button.height(30);
                                                                                Button.borderRadius(15);
                                                                                Button.backgroundColor(Color.Green);
                                                                                Button.fontColor(Color.White);
                                                                                Button.onClick(() => this.onInvokeAbility(this.parsedAppSurface!.bundleName, component.name));
                                                                            }, Button);
                                                                            Button.pop();
                                                                        });
                                                                    }
                                                                    // REMOVED: The DataShare-specific button logic for extensions
                                                                    else {
                                                                        this.ifElseBranchUpdateFunction(1, () => {
                                                                        });
                                                                    }
                                                                }, If);
                                                                If.pop();
                                                                Row.pop();
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Text.create(`Type: ${component.type}`);
                                                                    Text.fontSize(14);
                                                                    Text.fontColor(Color.Gray);
                                                                }, Text);
                                                                Text.pop();
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Text.create(`Visible: ${component.visible ? 'Yes' : 'No'}`);
                                                                    Text.fontSize(14);
                                                                    Text.fontColor(Color.Gray);
                                                                }, Text);
                                                                Text.pop();
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    If.create();
                                                                    // REMOVED: Display dataShareUri if available
                                                                    if (component.permissionsRequired && component.permissionsRequired.length > 0) {
                                                                        this.ifElseBranchUpdateFunction(0, () => {
                                                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                Text.create('Permissions Required:');
                                                                                Text.fontSize(14);
                                                                                Text.fontWeight(FontWeight.Medium);
                                                                                Text.margin({ top: 4 });
                                                                            }, Text);
                                                                            Text.pop();
                                                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                ForEach.create();
                                                                                const forEachItemGenFunction = _item => {
                                                                                    const perm = _item;
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        Text.create(`- ${perm}`);
                                                                                        Text.fontSize(12);
                                                                                        Text.fontColor(Color.Gray);
                                                                                    }, Text);
                                                                                    Text.pop();
                                                                                };
                                                                                this.forEachUpdateFunction(elmtId, component.permissionsRequired, forEachItemGenFunction);
                                                                            }, ForEach);
                                                                            ForEach.pop();
                                                                        });
                                                                    }
                                                                    else {
                                                                        this.ifElseBranchUpdateFunction(1, () => {
                                                                        });
                                                                    }
                                                                }, If);
                                                                If.pop();
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    If.create();
                                                                    if (component.skills && component.skills.length > 0) {
                                                                        this.ifElseBranchUpdateFunction(0, () => {
                                                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                Text.create('Skills (Intent Filters):');
                                                                                Text.fontSize(14);
                                                                                Text.fontWeight(FontWeight.Medium);
                                                                                Text.margin({ top: 4 });
                                                                            }, Text);
                                                                            Text.pop();
                                                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                ForEach.create();
                                                                                const forEachItemGenFunction = _item => {
                                                                                    const skill = _item;
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        Column.create();
                                                                                        Column.alignItems(HorizontalAlign.Start);
                                                                                        Column.margin({ bottom: 2 });
                                                                                    }, Column);
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        If.create();
                                                                                        if (skill.action) {
                                                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                                    Text.create(`  Action: ${skill.action}`);
                                                                                                    Text.fontSize(12);
                                                                                                    Text.fontColor(Color.Gray);
                                                                                                }, Text);
                                                                                                Text.pop();
                                                                                            });
                                                                                        }
                                                                                        else {
                                                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                                            });
                                                                                        }
                                                                                    }, If);
                                                                                    If.pop();
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        If.create();
                                                                                        if (skill.entity) {
                                                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                                    Text.create(`  Entity: ${skill.entity}`);
                                                                                                    Text.fontSize(12);
                                                                                                    Text.fontColor(Color.Gray);
                                                                                                }, Text);
                                                                                                Text.pop();
                                                                                            });
                                                                                        }
                                                                                        else {
                                                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                                            });
                                                                                        }
                                                                                    }, If);
                                                                                    If.pop();
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        If.create();
                                                                                        if (skill.scheme) {
                                                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                                    Text.create(`  Scheme: ${skill.scheme}`);
                                                                                                    Text.fontSize(12);
                                                                                                    Text.fontColor(Color.Gray);
                                                                                                }, Text);
                                                                                                Text.pop();
                                                                                            });
                                                                                        }
                                                                                        else {
                                                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                                            });
                                                                                        }
                                                                                    }, If);
                                                                                    If.pop();
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        If.create();
                                                                                        if (skill.type) {
                                                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                                    Text.create(`  Type: ${skill.type}`);
                                                                                                    Text.fontSize(12);
                                                                                                    Text.fontColor(Color.Gray);
                                                                                                }, Text);
                                                                                                Text.pop();
                                                                                            });
                                                                                        }
                                                                                        else {
                                                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                                            });
                                                                                        }
                                                                                    }, If);
                                                                                    If.pop();
                                                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                        If.create();
                                                                                        if (skill.utd && skill.utd.length > 0) {
                                                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                                                    Text.create(`  UTD: ${skill.utd.join(', ')}`);
                                                                                                    Text.fontSize(12);
                                                                                                    Text.fontColor(Color.Gray);
                                                                                                }, Text);
                                                                                                Text.pop();
                                                                                            });
                                                                                        }
                                                                                        else {
                                                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                                            });
                                                                                        }
                                                                                    }, If);
                                                                                    If.pop();
                                                                                    Column.pop();
                                                                                };
                                                                                this.forEachUpdateFunction(elmtId, component.skills, forEachItemGenFunction);
                                                                            }, ForEach);
                                                                            ForEach.pop();
                                                                        });
                                                                    }
                                                                    else {
                                                                        this.ifElseBranchUpdateFunction(1, () => {
                                                                        });
                                                                    }
                                                                }, If);
                                                                If.pop();
                                                                Column.pop();
                                                            };
                                                            this.forEachUpdateFunction(elmtId, this.parsedAppSurface.exposedComponents, forEachItemGenFunction);
                                                        }, ForEach);
                                                        ForEach.pop();
                                                    });
                                                }
                                            }, If);
                                            If.pop();
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Button.createWithLabel('View Raw Parsed JSON');
                                                Button.margin({ top: 16 });
                                                Button.backgroundColor(Color.Blue);
                                                Button.fontColor(Color.White);
                                                Button.onClick(() => {
                                                    this.currentAppDetails = this.currentAppSurfaceJson;
                                                    this.detailsViewMode = 'raw';
                                                });
                                            }, Button);
                                            Button.pop();
                                            Column.pop();
                                        });
                                    }
                                    else {
                                        this.ifElseBranchUpdateFunction(1, () => {
                                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                Text.create('No parsed app surface data available. Please click "Info" button for an app.');
                                                Text.fontSize(16);
                                                Text.fontColor(Color.Gray);
                                                Text.padding(10);
                                                Text.textAlign(TextAlign.Center);
                                            }, Text);
                                            Text.pop();
                                        });
                                    }
                                }, If);
                                If.pop();
                            });
                        }
                    }, If);
                    If.pop();
                    Scroll.pop();
                    Column.pop();
                });
            }
            else if (this.currentPage === 'abilityDetails' && this.selectedAbility) {
                this.ifElseBranchUpdateFunction(3, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                        Column.padding(16);
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Button to return to ability list
                        Button.createWithLabel('← Back to abilities');
                        // Button to return to ability list
                        Button.onClick(() => {
                            this.currentPage = 'vulnerableAbilities';
                            this.selectedAbility = null;
                        });
                        // Button to return to ability list
                        Button.margin({ bottom: 16 });
                    }, Button);
                    // Button to return to ability list
                    Button.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Title
                        Text.create('Ability Details');
                        // Title
                        Text.fontSize(20);
                        // Title
                        Text.fontWeight(FontWeight.Bold);
                        // Title
                        Text.margin({ bottom: 16 });
                    }, Text);
                    // Title
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Basic Info.
                        Text.create(`App: ${this.selectedAbility.app}`);
                        // Basic Info.
                        Text.fontSize(14);
                        // Basic Info.
                        Text.fontWeight(FontWeight.Bold);
                        // Basic Info.
                        Text.margin({ bottom: 8 });
                    }, Text);
                    // Basic Info.
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Text.create(`Ability: ${this.selectedAbility.ability}`);
                        Text.fontSize(14);
                        Text.fontWeight(FontWeight.Bold);
                        Text.margin({ bottom: 10 });
                    }, Text);
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Show Skill if any
                        Text.create(`Skills:`);
                        // Show Skill if any
                        Text.fontSize(14);
                        // Show Skill if any
                        Text.fontWeight(FontWeight.Bold);
                        // Show Skill if any
                        Text.margin({ bottom: 5 });
                    }, Text);
                    // Show Skill if any
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        If.create();
                        if (this.selectedAbility.skills.length > 0) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Scroll.create();
                                    Scroll.padding(20);
                                    Scroll.borderRadius(6);
                                    Scroll.backgroundColor(0xFFF0F0F0);
                                    Scroll.margin({ bottom: 10 });
                                    Scroll.height('20%');
                                }, Scroll);
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Column.create();
                                    Column.margin({ bottom: 5 });
                                }, Column);
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    ForEach.create();
                                    const forEachItemGenFunction = _item => {
                                        const skill = _item;
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Column.create();
                                        }, Column);
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Text.create(`• Action: ${skill.action}`);
                                            Text.fontSize(13);
                                            Text.fontWeight(FontWeight.Bold);
                                            Text.textAlign(TextAlign.Start);
                                            Text.margin({ bottom: 2 });
                                        }, Text);
                                        Text.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Text.create(`  Entity: ${skill.entity}`);
                                            Text.fontSize(13);
                                            Text.textAlign(TextAlign.Start);
                                        }, Text);
                                        Text.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Text.create(`  Scheme: ${skill.scheme}`);
                                            Text.fontSize(13);
                                            Text.textAlign(TextAlign.Start);
                                        }, Text);
                                        Text.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Text.create(`  Type: ${skill.type}`);
                                            Text.fontSize(13);
                                            Text.textAlign(TextAlign.Start);
                                        }, Text);
                                        Text.pop();
                                        Column.pop();
                                    };
                                    this.forEachUpdateFunction(elmtId, this.selectedAbility.skills, forEachItemGenFunction);
                                }, ForEach);
                                ForEach.pop();
                                Column.pop();
                                Scroll.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                    Text.create('No skills associated.');
                                    Text.fontSize(13);
                                    Text.fontColor(Color.Gray);
                                    Text.margin({ bottom: 16 });
                                }, Text);
                                Text.pop();
                            });
                        }
                    }, If);
                    If.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Separator
                        Divider.create();
                        // Separator
                        Divider.margin({ top: 16, bottom: 16 });
                    }, Divider);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        // Text fields to pass want parameters
                        // TODO: Rework this input
                        Text.create('Launch Want');
                        // Text fields to pass want parameters
                        // TODO: Rework this input
                        Text.fontSize(16);
                        // Text fields to pass want parameters
                        // TODO: Rework this input
                        Text.fontWeight(FontWeight.Bold);
                        // Text fields to pass want parameters
                        // TODO: Rework this input
                        Text.margin({ bottom: 8 });
                    }, Text);
                    // Text fields to pass want parameters
                    // TODO: Rework this input
                    Text.pop();
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        TextInput.create({ placeholder: 'Action' });
                        TextInput.onChange(value => this.customWantAction = value);
                        TextInput.margin({ bottom: 8 });
                    }, TextInput);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        TextInput.create({ placeholder: 'Entity' });
                        TextInput.onChange(value => this.customWantEntity = value);
                        TextInput.margin({ bottom: 8 });
                    }, TextInput);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Button.createWithLabel('Invoke with Want');
                        Button.backgroundColor(Color.Green);
                        Button.onClick(() => {
                            if (this.selectedAbility) {
                                this.onInvokeAbilityWithWant(this.selectedAbility.app, this.selectedAbility.ability, this.customWantAction || '', this.customWantEntity || '');
                            }
                        });
                    }, Button);
                    Button.pop();
                    Column.pop();
                });
            }
            else {
                this.ifElseBranchUpdateFunction(4, () => {
                });
            }
        }, If);
        If.pop();
        Column.pop();
    }
    rerender() {
        this.updateDirtyElements();
    }
    static getEntryName(): string {
        return "Index";
    }
}
registerNamedRoute(() => new Index(undefined, {}), "", { bundleName: "com.dekra.harm0nyz3r", moduleName: "entry", pagePath: "pages/Index", pageFullPath: "entry/src/main/ets/pages/Index", integratedHsp: "false", moduleType: "followWithHap" });
