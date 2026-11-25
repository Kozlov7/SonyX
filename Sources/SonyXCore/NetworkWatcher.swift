import Foundation
import SystemConfiguration

/// Подписка на смену сети: macOS сообщает о смене маршрута по умолчанию
/// за доли секунды, не дожидаясь очередного опроса.
public final class NetworkWatcher {
    private var store: SCDynamicStore?
    private let queue: DispatchQueue
    private let onChange: ([String]) -> Void

    /// `onChange` получает список изменившихся ключей SCDynamicStore.
    public init(queue: DispatchQueue = .main, onChange: @escaping ([String]) -> Void) {
        self.queue = queue
        self.onChange = onChange
    }

    /// Возвращает false, если подписаться не удалось — тогда остаётся только опрос.
    @discardableResult
    public func start() -> Bool {
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: SCDynamicStoreCallBack = { _, changedKeys, info in
            guard let info else { return }
            let watcher = Unmanaged<NetworkWatcher>.fromOpaque(info).takeUnretainedValue()
            let keys = (changedKeys as? [String]) ?? []
            watcher.onChange(keys)
        }
        guard let store = SCDynamicStoreCreate(nil, "SonyX" as CFString, callback, &context) else {
            return false
        }

        // Global/IPv4 и Global/IPv6 меняются, когда меняется маршрут по умолчанию
        // (en0 ↔ utunNN). Interface/* — когда интерфейс появляется, исчезает или
        // получает адрес: туннель поднимается и падает именно так.
        let keys = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Global/DNS",
        ] as CFArray
        let patterns = [
            "State:/Network/Interface/.*/IPv4",
            "State:/Network/Interface/.*/IPv6",
        ] as CFArray
        guard SCDynamicStoreSetNotificationKeys(store, keys, patterns),
              SCDynamicStoreSetDispatchQueue(store, queue) else {
            return false
        }
        self.store = store
        return true
    }

    public func stop() {
        if let store {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        store = nil
    }

    deinit { stop() }
}
