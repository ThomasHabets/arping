#!/usr/bin/expect -f

# Usage: print_time.ex arping 192.168.0.1

log_user 0
eval spawn $argv

expect {
       -re ".*\n" {
         send_user [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S" ]
         send_user " $expect_out(buffer)"
         exp_continue
       }
}
