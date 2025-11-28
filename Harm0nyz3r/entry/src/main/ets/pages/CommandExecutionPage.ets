import hilog from '@ohos.hilog';

import { fileIo, fileUri } from '@kit.CoreFileKit'; // Added fileUri for URI to path conversion
import common from '@ohos.app.ability.common';
import resourceManager from '@ohos.resourceManager'; // Added for raw file access

// IMPORTANT: Ensure your native module is correctly built and linked.
// The name 'CommandInjectionModule' must match the NAPI_MODULE define in your C++ code.
import commandInjectionModule from 'libentry.so'; // Corrected: Changed to libentry.so

@Entry // @Entry because this is a new standalone page
@Component
struct CommandExecutionPage {
  // Paths where the binaries will be written in the sandbox.
  @State bmBinaryWritePath: string = '';
  @State shBinaryWritePath: string = '';

  // Inputs for executing arbitrary commands (replacing manualCommandInput)
  @State executeBinaryPathInput: string = '/system/bin/toybox'; // Default to toybox
  @State executeCommandArgsInput: string = '';

  // Output from executing commands
  @State commandExecutionOutput: string = '';

  @State feedbackMessage: string = 'Initializing...';

  onPageShow() {
    this.commandExecutionOutput = '';
    this.feedbackMessage = 'Initializing...';
    this.executeBinaryPathInput = '/system/bin/toybox';
    this.executeCommandArgsInput = '';
    // Automatically load and write binaries when the page shows
    this.initializeAndWriteBinaries();
  }

  // New function to automatically load and write binaries
  async initializeAndWriteBinaries() {
    let context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
    let successCount = 0;
    let failCount = 0;
    let writtenPaths: string[] = [];

    try {
      if (!context.resourceManager) {
        this.feedbackMessage = `Error: ResourceManager not available. Cannot load raw binaries.`;
        hilog.error(0x0000, 'BinaryExecTestPage', `ResourceManager is null.`);
        return;
      }
      const filesDir = await context.filesDir;

      // Function to load and write a single raw file
      const loadAndWrite = async (fileName: string) => {
        try {
          const buffer = await context.resourceManager.getRawFileContent(fileName);
          const targetPath = `${filesDir}/${fileName}`;

          hilog.info(0x0000, 'BinaryExecTestPage', `Attempting to write raw binary '${fileName}' to: ${targetPath}`);

          const file = fileIo.openSync(targetPath, fileIo.OpenMode.CREATE | fileIo.OpenMode.WRITE_ONLY);
          fileIo.writeSync(file.fd, new Uint8Array(buffer).buffer); // Write the ArrayBuffer
          fileIo.fsyncSync(file.fd);
          fileIo.closeSync(file.fd);

          writtenPaths.push(targetPath);
          hilog.info(0x0000, 'BinaryExecTestPage', `Raw binary '${fileName}' successfully written to ${targetPath}.`);
          return true;
        } catch (e) {
          const error: Error = e as Error;
          hilog.error(0x0000, 'BinaryExecTestPage', `Failed to load/write raw file '${fileName}': %{public}s`, error.message);
          return false;
        }
      };

      // Load and write 'bm'
      if (await loadAndWrite('bm')) {
        this.bmBinaryWritePath = writtenPaths[writtenPaths.length - 1];
        successCount++;
      } else {
        failCount++;
      }

      // Load and write 'sh'
      if (await loadAndWrite('sh')) {
        this.shBinaryWritePath = writtenPaths[writtenPaths.length - 1];
        successCount++;
      } else {
        failCount++;
      }

      if (successCount > 0) {
        this.feedbackMessage = `Initialization complete. Written ${successCount} binaries. Paths: ${this.bmBinaryWritePath}, ${this.shBinaryWritePath}.`;
        this.executeCommandArgsInput = `ls -l ${this.bmBinaryWritePath}`; // Suggest initial command to list the written binary
      } else {
        this.feedbackMessage = `Initialization failed. Could not write binaries. Check logs.`;
      }
      hilog.info(0x0000, 'BinaryExecTestPage', this.feedbackMessage);

    } catch (e) {
      const error: Error = e as Error;
      hilog.error(0x0000, 'BinaryExecTestPage', `Overall initialization failed: %{public}s`, error.message);
      this.feedbackMessage = `Overall initialization failed: ${error.message}`;
    }
  }

  // Function to execute an arbitrary command using the two input textboxes
  async executeArbitraryCommand() {
    if (!this.executeBinaryPathInput.trim()) {
      this.feedbackMessage = 'Please enter a binary path for execution.';
      return;
    }

    this.commandExecutionOutput = '';
    this.feedbackMessage = 'Executing command...';

    const binaryToExecute = this.executeBinaryPathInput.trim();
    const commandArguments = this.executeCommandArgsInput.trim();

    try {
      if (typeof commandInjectionModule === 'undefined' || typeof commandInjectionModule.executeCommand !== 'function') {
        this.feedbackMessage = 'Error: Native command execution function not loaded or is undefined.';
        hilog.error(0x0000, 'BinaryExecTestPage', `Native executeCommand function is not available.`);
        return;
      }

      hilog.info(0x0000, 'BinaryExecTestPage', `Attempting to execute: ${binaryToExecute} ${commandArguments}`);

      const output: string = await commandInjectionModule.executeCommand(binaryToExecute, commandArguments);
      this.commandExecutionOutput = output;
      this.feedbackMessage = `Command executed. Check output below for details.`;
      hilog.info(0x0000, 'BinaryExecTestPage', `Command output: ${output}`);

    } catch (e) {
      const error: Error = e as Error;
      hilog.error(0x0000, 'BinaryExecTestPage', `Command execution failed: %{public}s`, error.message);
      this.commandExecutionOutput = `Error: ${error.message}`;
      this.feedbackMessage = `Command execution failed. See output for error.`;
    }
  }

  build() {
    Scroll() {
      Column() {

        Text('Command Execution')
          .fontSize(23)
          .fontWeight(FontWeight.Bold)
          .margin({ bottom: 12 })
          .margin({ bottom: 24 })

        Text('Use these paths in the commands below to test `chmod` and execution.')
          .fontSize(14).fontColor(Color.Gray).margin({ bottom: 24 })
          .width('80%').textAlign(TextAlign.Center)
          .visibility((this.bmBinaryWritePath || this.shBinaryWritePath) ? Visibility.Visible : Visibility.None)

        Divider().strokeWidth(1).color(Color.Gray).margin({ top: 16, bottom: 16 }).width('80%')


        Text('Binary Path:')
          .fontSize(17)
          .width('80%')
          .textAlign(TextAlign.Start)
          .margin({ bottom: 4 })
        TextInput({ placeholder: 'e.g., /system/bin/toybox', text: this.executeBinaryPathInput })
          .onChange((val: string) => {
            this.executeBinaryPathInput = val;
          })
          .width('80%').height(40).borderRadius(8).border({ width: 1, color: '#D1D5DB' }).backgroundColor(Color.White)
          .margin({ bottom: 10 })

        Text('Command Arguments:')
          .fontSize(17)
          .width('80%')
          .textAlign(TextAlign.Start)
          .margin({ bottom: 4 })
        TextInput({ placeholder: `e.g., chmod 755 ${this.bmBinaryWritePath || '/path/to/binary'}`, text: this.executeCommandArgsInput })
          .onChange((val: string) => {
            this.executeCommandArgsInput = val;
          })
          .width('80%').height(80).borderRadius(8).border({ width: 1, color: '#D1D5DB' }).backgroundColor(Color.White)
          .margin({ bottom: 10 })

        Button('Execute Command')
          .width('80%').height(40).borderRadius(8).backgroundColor(0x4CAF50) // Green button
          .fontColor(Color.White).fontWeight(FontWeight.Medium)
          .onClick(() => this.executeArbitraryCommand())
          .margin({ bottom: 16 })

        Text('Command Output:')
          .fontSize(17)
          .fontWeight(FontWeight.Bold) // Changed from Semibold
          .margin({ bottom: 8 })
          .width('80%')
          .textAlign(TextAlign.Start)

        Scroll() {
          Text(this.commandExecutionOutput)
            .fontSize(14).fontFamily('monospace').width('100%').padding(12)
            .backgroundColor(0xF3F4F6).borderRadius(8).border({ width: 1, color: '#D1D5DB' })
        }
        .height(180)
        .width('80%')
        .scrollable(ScrollDirection.Vertical)
        .margin({ bottom: 30 })

      }
      .width('100%')
      .justifyContent(FlexAlign.Start)
      .alignItems(HorizontalAlign.Center)
      .padding({ top: 20, bottom: 20 })
    }
    .scrollable(ScrollDirection.Vertical)
    .width('100%')
    .height('100%');
  }
}
