//
//  VideoSurface.swift
//  PandaLink
//
//  SwiftUI 里嵌 `AVSampleBufferDisplayLayer` 的桥。
//  `AVSampleBufferDisplayLayer` 是 CALayer 子类，不能直接放 SwiftUI 里，
//  得包一层 UIView。
//

import SwiftUI
import AVFoundation
import UIKit

/// 承载 `AVSampleBufferDisplayLayer` 的 UIView
final class VideoSurfaceView: UIView {

    override static var layerClass: AnyClass { AVSampleBufferDisplayLayer.self }

    var displayLayer: AVSampleBufferDisplayLayer {
        // layerClass 保证是这个类型
        layer as! AVSampleBufferDisplayLayer
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .black
        let l = displayLayer
        l.videoGravity = .resizeAspect
        l.backgroundColor = UIColor.black.cgColor
        l.isOpaque = true
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        backgroundColor = .black
        let l = displayLayer
        l.videoGravity = .resizeAspect
        l.backgroundColor = UIColor.black.cgColor
        l.isOpaque = true
    }

    /// 显示层失败后需要 flush 才能继续收帧
    func recoverIfNeeded() {
        if displayLayer.status == .failed {
            displayLayer.flush()
        }
    }
}

/// SwiftUI 包装。`renderer` 由 `CarLinkSession` 持有，这里只把 layer 挂上去。
struct VideoSurface: UIViewRepresentable {

    let renderer: H264DisplayRenderer
    var aspect: CGFloat = 16.0 / 9.0

    func makeUIView(context: Context) -> VideoSurfaceView {
        let v = VideoSurfaceView()
        renderer.layer = v.displayLayer
        return v
    }

    func updateUIView(_ uiView: VideoSurfaceView, context: Context) {
        if renderer.layer !== uiView.displayLayer {
            renderer.layer = uiView.displayLayer
        }
        uiView.recoverIfNeeded()
    }
}
