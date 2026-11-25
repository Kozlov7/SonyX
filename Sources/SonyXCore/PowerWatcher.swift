import Foundation
import IOKit
import IOKit.pwr_mgt

/// Сон и пробуждение Mac. Перед сном — заморозить, после пробуждения — проверить:
/// туннель после сна поднимается не сразу, и программы не должны успеть
/// отправить что-то с домашнего адреса.
public final class PowerWatcher {
    public enum Event {
        case willSleep
        case didWake
    }

    // Макросы kIOMessage* в Swift не импортируются; значения из IOKit/IOMessage.h:
    // iokit_common_msg(x) = 0xe0000000 | x
    private static let willSleep: UInt32 = 0xe000_0280      // kIOMessageSystemWillSleep
    private static let canSleep: UInt32 = 0xe000_0270       // kIOMessageCanSystemSleep
    private static let hasPoweredOn: UInt32 = 0xe000_0300   // kIOMessageSystemHasPoweredOn
    private static let willPowerOn: UInt32 = 0xe000_0320    // kIOMessageSystemWillPowerOn

    private var rootPort: io_connect_t = 0
    private var notifyPort: IONotificationPortRef?
    private var notifier: io_object_t = 0
    private let queue: DispatchQueue
    private let onEvent: (Event) -> Void

    public init(queue: DispatchQueue = .main, onEvent: @escaping (Event) -> Void) {
        self.queue = queue
        self.onEvent = onEvent
    }

    @discardableResult
    public func start() -> Bool {
        let callback: IOServiceInterestCallback = { refcon, _, messageType, messageArgument in
            guard let refcon else { return }
            let watcher = Unmanaged<PowerWatcher>.fromOpaque(refcon).takeUnretainedValue()
            watcher.handle(messageType: messageType, argument: messageArgument)
        }
        rootPort = IORegisterForSystemPower(
            Unmanaged.passUnretained(self).toOpaque(),
            &notifyPort,
            callback,
            &notifier
        )
        guard rootPort != 0, let notifyPort else { return false }
        IONotificationPortSetDispatchQueue(notifyPort, queue)
        return true
    }

    private func handle(messageType: UInt32, argument: UnsafeMutableRawPointer?) {
        switch messageType {
        case Self.willSleep:
            onEvent(.willSleep)
            // Системе обязательно нужно ответить, иначе она ждёт до 30 секунд.
            IOAllowPowerChange(rootPort, Int(bitPattern: argument))
        case Self.canSleep:
            IOAllowPowerChange(rootPort, Int(bitPattern: argument))
        case Self.willPowerOn, Self.hasPoweredOn:
            // Приходят оба, с разницей в секунды; выдержка отсчитывается от последнего.
            onEvent(.didWake)
        default:
            break
        }
    }

    public func stop() {
        if let notifyPort {
            IODeregisterForSystemPower(&notifier)
            IOServiceClose(rootPort)
            IONotificationPortDestroy(notifyPort)
        }
        notifyPort = nil
        rootPort = 0
    }

    deinit { stop() }
}
