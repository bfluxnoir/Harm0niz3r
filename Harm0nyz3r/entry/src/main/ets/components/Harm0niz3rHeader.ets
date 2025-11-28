// New Header Component
@Component
export struct  Harm0nyz3rHeader {
  build() {
    Column() {
      Row({ space: 16 }) {
        // IMPORTANT: Ensure 'app.media.startIcon' exists in your project.
        // If you don't have this image, replace it with a valid resource or remove.
        // Using a placeholder image for demonstration purposes if app.media.startIcon is not available.
        Image($r('app.media.startIcon'))
          .width(48)
          .height(48)

        Column() {
          Text('Harm0nyz3r')
            .fontSize(32)
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.Black)
            .margin({ top: 6 })
          Text('HOS Security Tool')
            .fontSize(18)
            .fontWeight(FontWeight.Medium)
            .fontColor(Color.Gray)
            .margin({ top: 5 })
        }.padding(10)
      }
    }
    .alignItems(HorizontalAlign.Center)
    .margin({ top: 28, bottom: 16 }) // Provides vertical spacing for the header
  }
}