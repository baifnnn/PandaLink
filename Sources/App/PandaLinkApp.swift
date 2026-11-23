//
//  PandaLinkApp.swift
//  PandaLink
//
//  入口。iOS 16.1 起用 SwiftUI App 生命周期。
//

import SwiftUI

@main
@MainActor
struct PandaLinkApp: App {
    @StateObject private var session = CarLinkSession()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(session)
                .preferredColorScheme(.dark)
        }
    }
}
