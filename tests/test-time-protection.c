/*
 * Copyright (c) 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include <config.h>
#undef NDEBUG

#include "dpif-netdev-time-protection.h"

#include <limits.h>

#include "ovstest.h"
#include "util.h"

static void
test_refill(void)
{
    struct tp_budget budget;

    tp_budget_init(&budget, 15000, 100);
    ovs_assert(tp_budget_get(&budget) == 15000);
    ovs_assert(tp_budget_charge(&budget, 16000, TP_CHARGE_RX) == -1000);
    ovs_assert(tp_budget_refill(&budget, 1099, 1000, 850, 15000) == -1000);
    ovs_assert(tp_budget_refill(&budget, 1100, 1000, 850, 15000) == -150);
    ovs_assert(tp_budget_refill(&budget, 3100, 1000, 850, 15000) == 1550);
    ovs_assert(tp_budget_refill(&budget, 100000, 1000, 850, 15000)
               == 15000);
}

static void
test_debt_and_saturation(void)
{
    struct tp_budget budget;

    tp_budget_init(&budget, 10, 0);
    ovs_assert(tp_budget_charge(&budget, UINT64_MAX, TP_CHARGE_ACTION)
               == INT64_MIN);
    ovs_assert(tp_budget_refill(&budget, 1, 1, INT64_MAX, 10) == -1);
    ovs_assert(tp_budget_refill(&budget, 2, 1, INT64_MAX, 10) == 10);

    tp_budget_init(&budget, 10, 0);
    ovs_assert(tp_budget_charge(&budget, UINT64_MAX, TP_CHARGE_ACTION)
               == INT64_MIN);
    ovs_assert(tp_budget_refill(&budget, UINT64_MAX, 1, UINT64_MAX, 10)
               == 10);

    tp_budget_init(&budget, 10, 100);
    ovs_assert(tp_budget_is_funded(&budget, 100, 10, 1, 10));
    ovs_assert(tp_budget_charge(&budget, 10, TP_CHARGE_TX) == 0);
    ovs_assert(!tp_budget_is_funded(&budget, 109, 10, 1, 10));
    ovs_assert(tp_budget_is_funded(&budget, 110, 10, 1, 10));
}

static void
test_stats(void)
{
    struct tp_budget budget;
    unsigned long long value;

    tp_budget_init(&budget, 100, 0);
    tp_budget_charge(&budget, 3, TP_CHARGE_RX);
    tp_budget_charge(&budget, 5, TP_CHARGE_ACTION);
    tp_budget_charge(&budget, 7, TP_CHARGE_TX);
    tp_budget_record_batch(&budget, false);
    tp_budget_record_batch(&budget, true);
    tp_budget_record_drop(&budget, 11);

    atomic_read_relaxed(&budget.rx_cycles, &value);
    ovs_assert(value == 3);
    atomic_read_relaxed(&budget.action_cycles, &value);
    ovs_assert(value == 5);
    atomic_read_relaxed(&budget.tx_cycles, &value);
    ovs_assert(value == 7);
    atomic_read_relaxed(&budget.funded_batches, &value);
    ovs_assert(value == 1);
    atomic_read_relaxed(&budget.slack_batches, &value);
    ovs_assert(value == 1);
    atomic_read_relaxed(&budget.dropped_packets, &value);
    ovs_assert(value == 11);

    tp_budget_clear_stats(&budget);
    atomic_read_relaxed(&budget.dropped_packets, &value);
    ovs_assert(value == 0);
    ovs_assert(tp_budget_get(&budget) == 85);
}

static void
test_time_protection_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_refill();
    test_debt_and_saturation();
    test_stats();
}

OVSTEST_REGISTER("test-time-protection", test_time_protection_main);
