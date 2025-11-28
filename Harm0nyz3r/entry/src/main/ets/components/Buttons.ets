@Component
export struct  InfoButton {
  build() {
    Button('Info')
      .width(60)
      .backgroundColor(Color.Blue)
      .margin({ right: 8 }) // Space between buttons
    }
}

@Component
export struct  BackButton {
  build() {
  Button('← Back to Apps')
    .margin({ bottom: 16 });
    }
}

@Component
export struct  RefreshButton {
  build() {
    Button('⟳ Refresh')
      .backgroundColor(Color.Grey)
      .fontColor(Color.White)
      .margin({ bottom: 16 });
  }
}

@Component
export struct InvokeButton {
  build() {
    Button('Invoke')
      .width(80)
      .backgroundColor(Color.Green)
  }
}
