pub fn dispatch_order(a_priority: i64, b_priority: i64, c_priority: i64) -> i64 {
    if a_priority <= b_priority && a_priority <= c_priority {
        if b_priority <= c_priority {
            123
        } else {
            132
        }
    } else if b_priority <= a_priority && b_priority <= c_priority {
        if a_priority <= c_priority {
            213
        } else {
            231
        }
    } else if a_priority <= b_priority {
        312
    } else {
        321
    }
}
