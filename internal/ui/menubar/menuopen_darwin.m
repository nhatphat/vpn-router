#import <Cocoa/Cocoa.h>

extern void vpnctlMenuOpened(void);

void vpnctlWatchMenuOpen(void) {
  [[NSNotificationCenter defaultCenter]
      addObserverForName:NSMenuDidBeginTrackingNotification
                  object:nil
                   queue:[NSOperationQueue mainQueue]
              usingBlock:^(NSNotification *note) {
                vpnctlMenuOpened();
              }];
}
