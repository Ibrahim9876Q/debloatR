import SwiftUI
import AppKit

struct Row: Decodable, Identifiable {
    let id: Int32
    let name: String
    let bytes: UInt64?
    let finding: String?
    let ready: Bool
}
struct Snapshot: Decodable {
    let used, total: UInt64
    let rows: [Row]
}
func memory(_ bytes: UInt64?) -> String {
    guard let bytes else { return "Unknown" }
    return String(format: "%.1f MiB", Double(bytes) / 1048576)
}
@MainActor final class Scan: ObservableObject {
    @Published var sample: Snapshot?
    @Published var status = ""
    private var worker: Process?
    func start() async {
        guard worker == nil else { return }
        let p = Process(), pipe = Pipe()
        guard let executable = Bundle.main.executableURL else { return }
        p.executableURL = executable.deletingLastPathComponent().appendingPathComponent("scanner")
        p.standardOutput = pipe
        worker = p
        status = "Scanning device…"
        defer { worker = nil }
        do {
            try p.run()
            for try await line in pipe.fileHandleForReading.bytes.lines {
                sample = try JSONDecoder().decode(Snapshot.self, from: Data(line.utf8))
                status = ""
            }
            status = "Scanner stopped. Scan again to restart."
        } catch {
            if p.isRunning { p.terminate() }
            status = error.localizedDescription
        }
    }
}
struct Dashboard: View {
    @StateObject private var scan = Scan()
    @State private var query = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("debloatR").font(.largeTitle.bold())
            if let s = scan.sample {
                Text("Memory overview").font(.title2)
                Text("\(memory(s.used)) in use of \(memory(s.total))")
                let rows = s.rows.sorted { ($0.bytes ?? 0) > ($1.bytes ?? 0) }
                let measured = rows.compactMap(\.bytes)
                Text("\(memory(measured.reduce(0,+))) attributed footprint across \(measured.count) of \(rows.count) processes. Kernel memory and shared allocations make this a different measure from system use.")
                let apps = NSWorkspace.shared.runningApplications
                let optional = rows.filter { r in r.bytes != nil && apps.contains { $0.processIdentifier == r.id && $0.activationPolicy == .regular && !$0.isActive } }
                if let r = optional.first {
                    Text("Consider quitting \(r.name) if you have finished using it (\(memory(r.bytes))). Save your work first.")
                }
                let back = rows.first { r in r.bytes != nil && apps.contains { $0.processIdentifier == r.id && $0.activationPolicy == .accessory } }
                if let back { Text("Background app to review: \(back.name) · \(memory(back.bytes)). Check its settings if you recognize it.") }
                let flags = rows.filter { $0.finding != nil }
                Text(flags.isEmpty ? (rows.contains(where: \.ready) ? "No sustained footprint growth detected." : "Collecting leak history…") : "\(flags.count) suspected leaks").font(.headline)
                ForEach(flags.prefix(5)) { r in Text("\(r.name) · \(r.finding ?? "")").font(.caption) }
                TextField("Search processes by name or PID", text:$query)
                Table(rows.filter {query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || String($0.id).contains(query)}) {
                    TableColumn("Process", value: \.name)
                    TableColumn("PID") { Text(String($0.id)) }
                    TableColumn("Memory footprint") { Text(memory($0.bytes)) }
                }
            } else {
                Spacer()
                Text("Scan device").font(.title.bold())
                Text("See where your Mac’s memory goes and which apps are worth reviewing.")
            }
            if !scan.status.isEmpty { Text(scan.status) }
            if scan.sample == nil || !scan.status.isEmpty {
                Button("Scan device") { Task { await scan.start() } }.disabled(scan.status == "Scanning device…")
            }
            if scan.sample == nil { Spacer() }
        }.padding(28).frame(minWidth:720,minHeight:500).preferredColorScheme(.dark).tint(.white)
    }
}
@main struct DebloatApp: App {
    var body: some Scene { Window("debloatR",id:"main") { Dashboard() } }
}
