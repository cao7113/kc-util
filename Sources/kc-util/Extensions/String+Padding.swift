extension String {
    var displayWidth: Int {
        reduce(0) { count, character in count + (character.isASCII ? 1 : 2) }
    }

    func padRightToWidth(_ width: Int) -> String {
        let currentWidth = displayWidth
        guard currentWidth < width else { return self }
        return self + String(repeating: " ", count: width - currentWidth)
    }
}