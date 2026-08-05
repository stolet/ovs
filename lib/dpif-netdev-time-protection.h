/*
 * Copyright (c) 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef DPIF_NETDEV_TIME_PROTECTION_H
#define DPIF_NETDEV_TIME_PROTECTION_H 1

#include <stdbool.h>
#include <stdint.h>

#include "ovs-atomic.h"

#define TP_DEFAULT_REFILL_US 1
#define TP_DEFAULT_MAX_BUDGET 15000
#define TP_DEFAULT_BOOST 0.85

enum tp_charge_type {
    TP_CHARGE_RX,
    TP_CHARGE_ACTION,
    TP_CHARGE_TX,
};

struct tp_budget {
    atomic_int64_t tokens;
    uint64_t last_refill;

    atomic_ullong rx_cycles;
    atomic_ullong action_cycles;
    atomic_ullong tx_cycles;
    atomic_ullong funded_batches;
    atomic_ullong slack_batches;
    atomic_ullong dropped_packets;
};

void tp_budget_init(struct tp_budget *, int64_t max_budget, uint64_t now);
int64_t tp_budget_get(const struct tp_budget *);
int64_t tp_budget_refill(struct tp_budget *, uint64_t now,
                         uint64_t period_cycles, uint64_t quantum,
                         int64_t max_budget);
int64_t tp_budget_charge(struct tp_budget *, uint64_t cycles,
                         enum tp_charge_type);
bool tp_budget_is_funded(struct tp_budget *, uint64_t now,
                         uint64_t period_cycles, uint64_t quantum,
                         int64_t max_budget);
void tp_budget_record_batch(struct tp_budget *, bool slack);
void tp_budget_record_drop(struct tp_budget *, uint64_t packets);
void tp_budget_clear_stats(struct tp_budget *);

#endif /* dpif-netdev-time-protection.h */
