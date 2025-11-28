@Component
export struct LoadingIcon {
  build() {
    Column() {
      LoadingProgress() // El cuerpo del componente no está dentro del método build()
      .width(20)
      .height(20)
      .margin({ top: 16, right: 8 });
      Text('Loading ability list...')
      .fontSize(14)
      .fontColor(Color.Grey);
      }
    }
}