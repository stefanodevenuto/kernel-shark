// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    sched_events.c
 *  @brief
 */

// C
#include <stdlib.h>
#include <stdio.h>

// trace-cmd
#include "trace-cmd/trace-cmd.h"

// KernelShark
#include "plugins/sched_events.h"
#include "libkshark-tepdata.h"

/** Plugin context instance. */

//! @cond Doxygen_Suppress

typedef unsigned long long tep_num_field_t;

#define PREV_STATE_SHIFT	((int) ((sizeof(ks_num_field_t) - 1) * 8))

#define PREV_STATE_MASK		(((ks_num_field_t) 1 << 8) - 1)

#define PID_MASK		(((ks_num_field_t) 1 << PREV_STATE_SHIFT) - 1)

//! @endcond

static void plugin_sched_set_pid(ks_num_field_t *field,
				 tep_num_field_t pid)
{
	*field &= ~PID_MASK;
	*field = pid & PID_MASK;
}

/**
 * @brief Retrieve the PID value from the data field stored in the
 *	  kshark_data_container object.
 *
 * @param field: Input location for the data field.
 */
int plugin_sched_get_pid(ks_num_field_t field)
{
	return field & PID_MASK;
}

/* Use the most significant byte to store the value of "prev_state". */
static void plugin_sched_set_prev_state(ks_num_field_t *field,
					tep_num_field_t prev_state)
{
	tep_num_field_t mask = PREV_STATE_MASK << PREV_STATE_SHIFT;
	*field &= ~mask;
	*field |= (prev_state & PREV_STATE_MASK) << PREV_STATE_SHIFT;
}

/**
 * @brief Retrieve the "prev_state" value from the data field stored in the
 *	  kshark_data_container object.
 *
 * @param field: Input location for the data field.
 */
int plugin_sched_get_prev_state(ks_num_field_t field)
{
	tep_num_field_t mask = PREV_STATE_MASK << PREV_STATE_SHIFT;
	return (field & mask) >> PREV_STATE_SHIFT;
}

/** A general purpose macro is used to define plugin context. */
KS_DEFINE_PLUGIN_CONTEXT(struct plugin_sched_context);

static bool plugin_sched_init_context(struct kshark_data_stream *stream,
				      struct plugin_sched_context *plugin_ctx)
{
	struct tep_event *event;
	bool wakeup_found;

	if (!kshark_is_tep(stream))
		return false;

	plugin_ctx->tep = kshark_get_tep(stream);
	event = tep_find_event_by_name(plugin_ctx->tep,
				       "sched", "sched_switch");
	if (!event)
		return false;

	plugin_ctx->sched_switch_event = event;
	plugin_ctx->sched_switch_next_field =
		tep_find_any_field(event, "next_pid");

	plugin_ctx->sched_switch_comm_field =
		tep_find_field(event, "next_comm");

	plugin_ctx->sched_switch_prev_state_field =
		tep_find_field(event, "prev_state");

	wakeup_found = define_wakeup_event(plugin_ctx->tep,
					   &plugin_ctx->sched_waking_event);

	if (wakeup_found) {
		plugin_ctx->sched_waking_pid_field =
			tep_find_any_field(plugin_ctx->sched_waking_event, "pid");
	}

	plugin_ctx->second_pass_done = false;

	plugin_ctx->ss_data = kshark_init_data_container();
	plugin_ctx->sw_data = kshark_init_data_container();
	if (!plugin_ctx->ss_data ||
	    !plugin_ctx->sw_data)
		return false;

	return true;
}

static void plugin_sched_swith_action(struct kshark_data_stream *stream,
				      void *rec, struct kshark_entry *entry)
{
	struct tep_record *record = (struct tep_record *) rec;
	struct plugin_sched_context *plugin_ctx;
	unsigned long long next_pid, prev_state;
	ks_num_field_t ks_field;
	int ret;

	plugin_ctx = __get_context(stream->stream_id);
	if (!plugin_ctx)
		return;

	ret = tep_read_number_field(plugin_ctx->sched_switch_next_field,
				    record->data, &next_pid);

	if (ret == 0 && next_pid >= 0) {
		plugin_sched_set_pid(&ks_field, entry->pid);

		ret = tep_read_number_field(plugin_ctx->sched_switch_prev_state_field,
					    record->data, &prev_state);

		if (ret == 0)
			plugin_sched_set_prev_state(&ks_field, prev_state);

		kshark_data_container_append(plugin_ctx->ss_data, entry, ks_field);
		entry->pid = next_pid;
	}
}

static void plugin_sched_wakeup_action(struct kshark_data_stream *stream,
				       void *rec, struct kshark_entry *entry)
{
	struct tep_record *record = (struct tep_record *) rec;
	struct plugin_sched_context *plugin_ctx;
	unsigned long long val;
	int ret;

	plugin_ctx = __get_context(stream->stream_id);
	if (!plugin_ctx)
		return;

	ret = tep_read_number_field(plugin_ctx->sched_waking_pid_field,
				    record->data, &val);

	if (ret == 0)
		kshark_data_container_append(plugin_ctx->sw_data, entry, val);
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	printf("--> sched init %i\n", stream->stream_id);
	struct plugin_sched_context *plugin_ctx;

	plugin_ctx = __init(stream->stream_id);
	if (!plugin_ctx || !plugin_sched_init_context(stream, plugin_ctx)) {
		__close(stream->stream_id);
		return 0;
	}

	kshark_register_event_handler(stream,
				      plugin_ctx->sched_switch_event->id,
				      plugin_sched_swith_action);

	kshark_register_event_handler(stream,
				      plugin_ctx->sched_waking_event->id,
				      plugin_sched_wakeup_action);

	kshark_register_draw_handler(stream, plugin_draw);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	printf("<-- sched close %i\n", stream->stream_id);
	struct plugin_sched_context *plugin_ctx;
	int sd = stream->stream_id;

	plugin_ctx = __get_context(sd);
	if (!plugin_ctx)
		return 0;

	kshark_unregister_event_handler(stream,
					plugin_ctx->sched_switch_event->id,
					plugin_sched_swith_action);

	kshark_unregister_event_handler(stream,
					plugin_ctx->sched_waking_event->id,
					plugin_sched_wakeup_action);

	kshark_unregister_draw_handler(stream, plugin_draw);

	__close(sd);

	return 1;
}

/** Initialize the control interface of the plugin. */
void *KSHARK_MENU_PLUGIN_INITIALIZER(void *gui_ptr)
{
	printf("--> sched init menu\n");
	return plugin_set_gui_ptr(gui_ptr);
}
