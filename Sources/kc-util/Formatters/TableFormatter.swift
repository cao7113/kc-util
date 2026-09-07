enum TableFormatter {
    static func line(character: Character, width: Int) -> String {
        String(repeating: character, count: width)
    }
}