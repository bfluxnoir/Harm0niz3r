@Component
export struct  IndicatorCircle {
  @Prop status: boolean;

  build() {
    Circle()
      .width(10)
      .height(10)
      .fill(this.status ? Color.Green : Color.Red); // Green if running, Red if not
  }
}