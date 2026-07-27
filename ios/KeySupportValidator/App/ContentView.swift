import SwiftUI

struct ContentView: View {

    @StateObject private var model = ScanViewModel()
    // Expanded by default: the trust chain is the substance of a successful
    // validation, not an optional detail to go hunting for.
    @State private var pathExpanded = true

    var body: some View {
        ZStack {
            palette.background.ignoresSafeArea()

            VStack(spacing: 16) {
                Spacer()
                statusContent
                Spacer()
                scanButton
            }
            .padding(24)
        }
        .animation(.easeInOut(duration: 0.2), value: model.state)
        .onChange(of: model.state) { _, newState in
            guard newState.isTerminal else { return }
            pathExpanded = true
            let generator = UINotificationFeedbackGenerator()
            if case .success = newState {
                generator.notificationOccurred(.success)
            } else {
                generator.notificationOccurred(.error)
            }
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var statusContent: some View {
        switch model.state {
        case .unsupported:
            headline("NFC Not Available")
            body("This iPhone cannot read ISO 7816 smart cards. An iPhone 7 or later running iOS 13 or newer is required.")

        case .idle:
            headline("Ready to Scan")
            body("Tap Scan Card, then hold your PIV, CAC, or TWIC card against the top of your iPhone.")

        case .readingCertificate:
            headline("Reading Certificate…")

        case .verifyingCard:
            headline("Verifying Smart Card…")
            body("Performing Proof of Possession")

        case .validatingNetwork:
            headline("Validating Card Authentication Certificate")
            ProgressView()
                .tint(palette.foreground)
                .padding(.top, 8)

        case .success(let subject, let path):
            // The green screen means two independent checks passed, and a relying
            // party cares more about the second. Crediting only Proof of Possession
            // (as the Android app does) hides the fact that VSS was consulted at all.
            headline("Credential Valid")
            checkLine("Proof of Possession verified")
            checkLine("Validated against KeySupport VSS")
            body(subject)
            if !path.isEmpty {
                certificatePathCard(path)
            }

        case .failure(let title, let message):
            headline(title)
            body(message)
        }
    }

    private var scanButton: some View {
        Button {
            Task { await model.scan() }
        } label: {
            Text(model.state.isTerminal ? "Scan Another Card" : "Scan Card")
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .disabled(model.isBusy || model.state == .unsupported)
        // Unlike Android's reader mode, iOS cannot poll for tags in the
        // background — every scan must be user-initiated and shows Apple's
        // own system sheet, so an explicit button is mandatory here.
    }

    private func certificatePathCard(_ path: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Certificate Path")
                    .font(.subheadline.bold())
                Spacer()
                Image(systemName: pathExpanded ? "chevron.up" : "chevron.down")
                    .font(.caption.bold())
            }

            if pathExpanded {
                ForEach(Array(path.enumerated()), id: \.offset) { index, name in
                    Text("\(index + 1). \(name)")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .foregroundStyle(palette.foreground)
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(Color(hex: 0xC8E6C9), in: RoundedRectangle(cornerRadius: 12))
        .contentShape(Rectangle())
        .onTapGesture { pathExpanded.toggle() }
        .padding(.top, 16)
    }

    // MARK: - Building blocks

    /// A single confirmed check on the success screen.
    private func checkLine(_ text: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.seal.fill")
            Text(text)
        }
        .font(.subheadline.weight(.medium))
        .foregroundStyle(palette.foreground)
        .padding(.top, 6)
    }

    private func headline(_ text: String) -> some View {
        Text(text)
            .font(.title2.bold())
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.foreground)
    }

    private func body(_ text: String) -> some View {
        Text(text)
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.foreground)
            .padding(.top, 8)
    }

    private var palette: (background: Color, foreground: Color) {
        switch model.state {
        case .success:
            return (Color(hex: 0xE8F5E9), Color(hex: 0x1B5E20))
        case .failure:
            return (Color(hex: 0xFFEBEE), Color(hex: 0xB71C1C))
        case .readingCertificate, .verifyingCard, .validatingNetwork:
            return (Color(.secondarySystemBackground), Color(.label))
        case .idle, .unsupported:
            return (Color(.systemBackground), Color(.label))
        }
    }
}

private extension Color {
    /// Mirrors the Material palette the Android app hardcodes, so both apps read
    /// identically. These are fixed light-mode values by design.
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0,
            opacity: 1.0
        )
    }
}

#Preview {
    ContentView()
}
