@Component
export struct SearchBar {
  @Prop searchText: string = '';

  build() {
    TextInput({ text: this.searchText, placeholder: 'Search apps...' })
      .placeholderColor(Color.Gray)
      .placeholderFont({ size: 14 })
      .backgroundColor(0xFFF8F8F8)
      .borderRadius(8)
      .padding({ left: 10, right: 10, top: 8, bottom: 8 })
      .margin({ bottom: 10, left: 16, right: 16 })
  }
}