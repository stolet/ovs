/*
 * Copyright (c) 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include <config.h>

#include "dpif-netdev-time-protection.h"

#include <limits.h>

static uint64_t
sat_mul_u64(uint64_t a, uint64_t b)
{
    return b && a > UINT64_MAX / b ? UINT64_MAX : a * b;
}

static void
stat_add(atomic_ullong *stat, unsigned long long value)
{
    unsigned long long old;

    atomic_add_relaxed(stat, value, &old);
}

void
tp_budget_init(struct tp_budget *budget, int64_t max_budget, uint64_t now)
{
    atomic_init(&budget->tokens, max_budget);
    budget->last_refill = now;
    atomic_init(&budget->rx_cycles, 0);
    atomic_init(&budget->action_cycles, 0);
    atomic_init(&budget->tx_cycles, 0);
    atomic_init(&budget->funded_batches, 0);
    atomic_init(&budget->slack_batches, 0);
    atomic_init(&budget->dropped_packets, 0);
}

int64_t
tp_budget_get(const struct tp_budget *budget)
{
    int64_t tokens;

    atomic_read_relaxed(&budget->tokens, &tokens);
    return tokens;
}

int64_t
tp_budget_refill(struct tp_budget *budget, uint64_t now,
                 uint64_t period_cycles, uint64_t quantum,
                 int64_t max_budget)
{
    uint64_t intervals, increment, room;
    int64_t tokens, updated;

    if (!period_cycles || now < budget->last_refill
        || now - budget->last_refill < period_cycles) {
        return tp_budget_get(budget);
    }

    intervals = (now - budget->last_refill) / period_cycles;
    budget->last_refill += intervals * period_cycles;
    increment = sat_mul_u64(intervals, quantum);
    tokens = tp_budget_get(budget);

    room = tokens >= 0
           ? (uint64_t) (max_budget - tokens)
           : (uint64_t) max_budget + (uint64_t) (-(tokens + 1)) + 1;
    if (tokens >= max_budget || increment >= room) {
        updated = max_budget;
    } else if (tokens < 0) {
        uint64_t debt = (uint64_t) (-(tokens + 1)) + 1;

        updated = increment < debt
                  ? tokens + (int64_t) increment
                  : (int64_t) (increment - debt);
    } else {
        updated = tokens + (int64_t) increment;
    }
    atomic_store_relaxed(&budget->tokens, updated);
    return updated;
}

int64_t
tp_budget_charge(struct tp_budget *budget, uint64_t cycles,
                 enum tp_charge_type type)
{
    uint64_t available;
    int64_t tokens, updated;

    tokens = tp_budget_get(budget);
    available = tokens >= 0
                ? (uint64_t) tokens + (uint64_t) INT64_MAX + 1
                : (uint64_t) (tokens - INT64_MIN);
    if (cycles >= available) {
        updated = INT64_MIN;
    } else if (cycles <= INT64_MAX) {
        updated = tokens - (int64_t) cycles;
    } else {
        updated = INT64_MIN + (int64_t) (available - cycles);
    }
    atomic_store_relaxed(&budget->tokens, updated);

    switch (type) {
    case TP_CHARGE_RX:
        stat_add(&budget->rx_cycles, cycles);
        break;
    case TP_CHARGE_ACTION:
        stat_add(&budget->action_cycles, cycles);
        break;
    case TP_CHARGE_TX:
        stat_add(&budget->tx_cycles, cycles);
        break;
    }

    return updated;
}

bool
tp_budget_is_funded(struct tp_budget *budget, uint64_t now,
                    uint64_t period_cycles, uint64_t quantum,
                    int64_t max_budget)
{
    return tp_budget_refill(budget, now, period_cycles, quantum,
                            max_budget) > 0;
}

void
tp_budget_record_batch(struct tp_budget *budget, bool slack)
{
    if (slack) {
        stat_add(&budget->slack_batches, 1);
    } else {
        stat_add(&budget->funded_batches, 1);
    }
}

void
tp_budget_record_drop(struct tp_budget *budget, uint64_t packets)
{
    stat_add(&budget->dropped_packets, packets);
}

void
tp_budget_clear_stats(struct tp_budget *budget)
{
    atomic_store_relaxed(&budget->rx_cycles, 0);
    atomic_store_relaxed(&budget->action_cycles, 0);
    atomic_store_relaxed(&budget->tx_cycles, 0);
    atomic_store_relaxed(&budget->funded_batches, 0);
    atomic_store_relaxed(&budget->slack_batches, 0);
    atomic_store_relaxed(&budget->dropped_packets, 0);
}
