#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "libkshark.h"
#include "libkshark-tepdata.h"

/* Recovered from the Kernel*/
#define SVM_EXIT_HLT 120 /* 0x078 */
#define SVM_EXIT_MSR 124 /* 0x07c */
#define VMX_EXIT_REASON_HLT 12
#define VMX_EXIT_MSR_WRITE  32

/* Relevant hrtimer events */
#define HRTIMER_START       "timer/hrtimer_start"
#define HRTIMER_CANCEL      "timer/hrtimer_cancel"
#define HRTIMER_EXPIRE_EXIT "timer/hrtimer_expire_exit"

/* Relevant cpu_idle events */
#define CPU_IDLE       "power/cpu_idle"

/* Relevant KVM events */
#define KVM_ENTRY "kvm/kvm_entry"
#define KVM_EXIT "kvm/kvm_exit"

#define PREV_STATE 4294967295 /* -1 */

#define INITIAL_CAPACITY 20

struct samples
{
    uint64_t* samples;

    int count;
    int capacity;

    uint64_t sum;
    float mean;
    float variance;
    float sd;
};

struct cpu
{
    int state;

    uint64_t hrtimer_event;
    uint64_t cpu_idle_event;
};

struct custom_stream
{
    struct kshark_data_stream* original_stream;
    struct cpu** cpus;
};

/**
 * Checks if a stream_id represents a guest.
 * If so, @host contains the corresponding host stream_id
 */
int is_guest(int stream_id,
         struct kshark_host_guest_map* mapping,
         int n_mapping, int* host)
{
    for (int i = 0; i < n_mapping; i++) {
        if (mapping[i].guest_id == stream_id) {
            *host = mapping[i].host_id;
            return 1;
        }
    }

    return 0;
}

/**
 * Recover guest stream_id from host VMentry/VMexit event.
 * In case of success, @guest_id will contain the guest stream_id.
 */
int guest_id_from_host_entry_exit(struct kshark_host_guest_map* mapping,
                  int n_mapping, int* guest_id,
                  struct kshark_entry* entry)
{
    struct kshark_data_stream* stream;
    int pid;

    stream = kshark_get_stream_from_entry(entry);
    pid = kshark_get_pid(entry);

    for (int i = 0; i < n_mapping; i++)
        if (mapping[i].host_id == stream->stream_id)
            for (int j = 0; j < mapping[i].vcpu_count; j++)
                if (mapping[i].cpu_pid[j] == pid) {
                    *guest_id = mapping[i].guest_id;
                    return 1;
                }

    return 0;
}

void initialize_sample_array(struct samples** samples, int capacity)
{
	*samples = calloc(1, sizeof(**samples));
	(*samples)->capacity = capacity;

	(*samples)->samples = calloc(capacity, sizeof(*(*samples)->samples));
}

void add_sample(struct samples* samples, uint64_t sample)
{
	if (samples->count == samples->capacity) {
        samples->capacity = samples->capacity * 2;
        samples->samples = realloc(samples->samples, samples->capacity * sizeof(*samples->samples));
	}

    samples->samples[samples->count] = sample;
    samples->count = samples->count + 1;
    samples->sum = samples->sum + sample;
    samples->mean = samples->sum / (float) samples->count;
}

void compute_variance_and_sd(struct samples* samples)
{
    uint64_t aux = 0;
    for (int i = 0; i < samples->count; i++) {
        aux += pow(samples->samples[i] - samples->mean, 2);
    }

    samples->variance = aux / (float) samples->count;
    samples->sd = sqrt(samples->variance);
}

void print_stats(struct samples* samples)
{
    printf("N_Samples: %d,\tMean: %f,\tVariance: %f,\tSD: %f\n",
        samples->count,
        samples->mean,
        samples->variance,
        samples->sd);
}

void free_sample_array(struct samples* samples)
{
    free(samples->samples);
    free(samples);
}

void print_entry(struct kshark_entry* entry)
{
    struct kshark_data_stream* stream;
    char* event_name;

    stream = kshark_get_stream_from_entry(entry);
    event_name = kshark_get_event_name(entry);

    printf("      %d: %s-%d, %" PRId64 " [%03d]:%s\t%s\n",
        stream->stream_id,
        kshark_get_task(entry),
        kshark_get_pid(entry),
        entry->ts,
        entry->cpu,
        event_name,
        kshark_get_info(entry));
}

void free_data(struct kshark_context *kshark_ctx,
           struct custom_stream** custom_streams,
           struct kshark_entry** entries, int n_entries,
           struct kshark_host_guest_map* host_guest_mapping,
           int n_guest)
{
    struct custom_stream* custom_stream;

    for (int i = 0; i < kshark_ctx->n_streams; i++) {
        custom_stream = custom_streams[i];

        for (int j = 0; j < custom_stream->original_stream->n_cpus; j++)
            free(custom_stream->cpus[j]);

        free(custom_stream->cpus);
        free(custom_stream);
    }
    free(custom_streams);

    for (int i = 0; i < n_entries; i++)
        free(entries[i]);
    free(entries);

    kshark_tracecmd_free_hostguest_map(host_guest_mapping, n_guest);
}

int main(int argc, char **argv)
{
    struct kshark_host_guest_map* host_guest_mapping;
    struct custom_stream** custom_streams;
    struct custom_stream* custom_stream;
    struct custom_stream* guest_stream;
    struct custom_stream* host_stream;
    struct kshark_data_stream* stream;
    struct kshark_context* kshark_ctx;
    struct kshark_entry** entries;
    struct kshark_entry* current;
    ssize_t n_entries;
    char* event_name;
    int64_t reason;
    int64_t info1;
    int64_t state;
    int64_t vcpu;
    int guest_id;
    int n_guest;
    int host;
    int v_i;
    int sd;

    struct samples* hrtimer_events = NULL;
    struct samples* cpu_idle_events = NULL;

    initialize_sample_array(&hrtimer_events, INITIAL_CAPACITY);
    initialize_sample_array(&cpu_idle_events, INITIAL_CAPACITY);

    kshark_ctx = NULL;
    if (!kshark_instance(&kshark_ctx))
        return 1;

    custom_streams = malloc(sizeof(*custom_streams) * (argc-1));

    for (int i = 1; i < argc; i++) {
        sd = kshark_open(kshark_ctx, argv[i]);
        if (sd < 0) {
            kshark_free(kshark_ctx);
            return 1;
        }

        kshark_tep_init_all_buffers(kshark_ctx, sd);

        /**
         * Creating custom streams in order to keep track if a
         * pCPU is executing code of a vCPU and, if so, which vCPU.
         */
        custom_stream = malloc(sizeof(*custom_stream));
        custom_stream->original_stream = kshark_get_data_stream(kshark_ctx, sd);
        custom_stream->cpus = malloc(custom_stream->original_stream->n_cpus * sizeof(*custom_stream->cpus));

        for (int i = 0; i < custom_stream->original_stream->n_cpus; i++) {
            custom_stream->cpus[i] = malloc(sizeof(*custom_stream->cpus[i]));
            memset(custom_stream->cpus[i], -1, sizeof(*custom_stream->cpus[i]));
        }

        custom_streams[i-1] = custom_stream;
    }

    host_guest_mapping = NULL;
    n_guest = kshark_tracecmd_get_hostguest_mapping(&host_guest_mapping);
    if (n_guest < 0) {
        printf("Failed mapping: %d\n", n_guest);
        return 1;
    }

    entries = NULL;
    n_entries = kshark_load_all_entries(kshark_ctx, &entries);

    for (int i = 0; i < n_entries; ++i) {
        current = entries[i];

        stream = kshark_get_stream_from_entry(current);
        event_name = kshark_get_event_name(current);

        custom_stream = custom_streams[stream->stream_id];

        if (!strcmp(event_name, KVM_ENTRY) || !strcmp(event_name, KVM_EXIT)) {
            if (kshark_read_event_field_int(current, "vcpu_id", &vcpu)) {
                printf("Error on recovering the vCPU field\n");
                return 1;
            }

            if (!guest_id_from_host_entry_exit(host_guest_mapping, n_guest, &guest_id, current)) {
                printf("Error on recovering guest stream ID\n");
                return 1;
            }

            /**
             * Workaround implemented in order to not mark as invalid initial guests events.
             * Implemented in this way since we can't know if after them we'll find a
             * kvm_entry or a kvm_exit (like it should be).
             */
            guest_stream = custom_streams[guest_id];
            guest_stream->cpus[vcpu]->state = 1;

            if (!strcmp(event_name, KVM_ENTRY)) {
                custom_stream->cpus[current->cpu]->state = vcpu;
            } else {
                custom_stream->cpus[current->cpu]->state = -1;

                if (kshark_read_event_field_int(current, "exit_reason", &reason)) {
                    printf("Error on recovering the reason field\n");
                    return 1;
                }

                /* If the current CPU found a possible new sample */
                if (custom_stream->cpus[current->cpu]->hrtimer_event != -1) {
                    if (reason == VMX_EXIT_MSR_WRITE || reason == SVM_EXIT_MSR) {
                        if (reason == SVM_EXIT_MSR) {
                            if (kshark_read_event_field_int(current, "info1", &info1)) {
                                printf("Error on recovering the reason field\n");
                                return 1;
                            }

                            /* If the reason is actually MSR_WRITE */
                            if (info1 != 1) {
                                continue;
                            } else printf("AMD: ");
                        } else printf("Intel: ");

                        printf("MSR found: %" PRId64 "\n", current->ts - custom_stream->cpus[current->cpu]->hrtimer_event);

                        add_sample(hrtimer_events, current->ts - custom_stream->cpus[current->cpu]->hrtimer_event);

                    }
                }

                if (custom_stream->cpus[current->cpu]->cpu_idle_event != -1) {
                    if (reason == SVM_EXIT_HLT || reason == VMX_EXIT_REASON_HLT) {
                        printf("CPU_IDLE found: %" PRId64 "\n", current->ts - custom_stream->cpus[current->cpu]->cpu_idle_event);
                        add_sample(cpu_idle_events, current->ts - custom_stream->cpus[current->cpu]->cpu_idle_event);
                    }
                }

                /* Reset values in case of unexpected VMExit reason */
                custom_stream->cpus[current->cpu]->hrtimer_event = -1;
                custom_stream->cpus[current->cpu]->cpu_idle_event = -1;
            }

        } else {

            /**
             * If the event comes from a guest, recover the pCPU where the event was executed
             * and check if it's NOT OUTSIDE a kvm_entry/kvm_exit block.
             */
            if (is_guest(stream->stream_id, host_guest_mapping, n_guest, &host)) {
                host_stream = custom_streams[host];

                for (v_i = 0; v_i < host_stream->original_stream->n_cpus; v_i++) {
                    if (current->cpu == host_stream->cpus[v_i]->state)
                    break;
                }

                /* If the event is checkable */
                if (custom_stream->cpus[current->cpu]->state != -1) {

                    if (v_i == host_stream->original_stream->n_cpus) {
                        //printf("%d G out:\t", i);
                    } else {

                        /* If the current event is relevant for the MSR analysis */
                        if ((!strcmp(event_name, HRTIMER_START) ||  !strcmp(event_name, HRTIMER_CANCEL) || !strcmp(event_name, HRTIMER_EXPIRE_EXIT)))
                            host_stream->cpus[v_i]->hrtimer_event = current->ts;

                        /* If the current event is relevant for the cpu_idle analysis */
                        if (!strcmp(event_name, CPU_IDLE)) {
                            if (kshark_read_event_field_int(current, "state", &state)) {
                                printf("Error on recovering the state field\n");
                                return 1;
                            }

                            /* If is not re-entering in the previous state */
                            if (state != PREV_STATE)
                                host_stream->cpus[v_i]->cpu_idle_event = current->ts;
                        }
                    }
                }

            /**
             * If the event comes from a host, recover the CPU that executed the event
             * and check if it's NOT INSIDE a kvm_entry/kvm_exit block.
             */
            } else {
                if (custom_stream->cpus[current->cpu]->state != -1) {
                    //printf("%d H in:\t", i);
                }
            }
        }

        //print_entry(entries[i]);
    }

    compute_variance_and_sd(hrtimer_events);
    compute_variance_and_sd(cpu_idle_events);

    printf("MSR:\t\t");
    print_stats(hrtimer_events);

    printf("CPU_IDLE:\t");
    print_stats(cpu_idle_events);

    free_sample_array(hrtimer_events);
    free_sample_array(cpu_idle_events);

    free_data(kshark_ctx, custom_streams, entries, n_entries, host_guest_mapping, n_guest);
    kshark_free(kshark_ctx);
}


