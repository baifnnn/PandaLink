//
//  ContentView.swift
//  PandaLink
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var session: CarLinkSession

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    statusCard
                    pinCard
                    channelCard
                    logCard
                }
                .padding(16)
            }
            .background(Color.black.opacity(0.02))
            .navigationTitle("PandaLink")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("清日志") { session.clearLogs() }
                        .font(.caption)
                }
            }
            .safeAreaInset(edge: .bottom) { bottomBar }
        }
    }

    // MARK: 状态

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle()
                    .fill(color(for: session.phase))
                    .frame(width: 10, height: 10)
                Text(session.phase.title)
                    .font(.headline)
                Spacer()
            }
            if !session.phoneIP.isEmpty {
                row("手机 IP", session.phoneIP)
            }
            if !session.carModel.isEmpty {
                row("车机型号", session.carModel)
            }
            if !session.sessionKeyHex.isEmpty {
                row("会话密钥", String(session.sessionKeyHex.prefix(16)) + "…")
            }
        }
        .card()
    }

    // MARK: PIN

    private var pinCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PIN 码").font(.subheadline).foregroundStyle(.secondary)
            HStack {
                TextField("留空表示不校验", text: $session.pin)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)
                Button("随机") { session.randomizePIN() }
                    .buttonStyle(.bordered)
            }
            Text("车机端输入此 PIN 才能完成配对（对齐 CarlinkHostActivity.z）")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .card()
    }

    // MARK: 通道

    private var channelCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("通道").font(.subheadline).foregroundStyle(.secondary)
            ForEach(ChannelRole.allCases, id: \.self) { role in
                HStack {
                    Text(role.label).font(.caption.monospaced())
                    Text(":\(role.port)").font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(session.frameCounts[role.label] ?? 0) 帧")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }
        .card()
    }

    // MARK: 日志

    private var logCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("日志").font(.subheadline).foregroundStyle(.secondary)
            if session.logs.isEmpty {
                Text("（空）").font(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(session.logs.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption2.monospaced())
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .frame(maxHeight: 260)
            }
        }
        .card()
    }

    // MARK: 底栏

    private var bottomBar: some View {
        HStack(spacing: 12) {
            Button {
                session.start()
            } label: {
                Label("启动监听", systemImage: "antenna.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Button {
                session.stop()
            } label: {
                Label("停止", systemImage: "stop.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .padding(16)
        .background(.bar)
    }

    // MARK: 小工具

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Text(v).font(.caption.monospaced())
        }
    }

    private func color(for phase: CarLinkSession.Phase) -> Color {
        switch phase {
        case .authenticated: return .green
        case .listening, .authenticating: return .yellow
        case .failed: return .red
        case .idle: return .gray
        }
    }
}

private extension View {
    func card() -> some View {
        self
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
    }
}

// 预览：`CarLinkSession` 是 @MainActor 隔离的，Swift 5 语言模式下这里只会给
// 「main actor-isolated initializer 在非隔离上下文调用」的警告，不影响编译。
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView().environmentObject(CarLinkSession())
    }
}
