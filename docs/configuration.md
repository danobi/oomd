# Configuration

## Design principles

oomd is designed to be as flexible and as extensible as possible. To that end,
oomd is configured via a declarative configuration file. The idea is you can
have a set of memory protection rules that are orthogonal and intuitive to
reason about. In a sense it's a lot like iptables chains work (but much better,
I promise).

## Schema

oomd configs have a loosely defined BNF:

    ARG:
    <string>=<string>

    NAME:
    <string>

    PLUGIN:
    [ NAME, [ARG[,ARG[,...]]] ]

    DETECTOR:
    PLUGIN

    DETECTOR_GROUP:
    [ NAME, DETECTOR[,DETECTOR[,...]] ]

    ACTION:
    PLUGIN

    RULESET:
    [
        NAME,
        "detectors": [ [DETECTOR_GROUP[,DETECTOR_GROUP[,...]]] ],
        "actions": [ [ACTION[,ACTION[,...]]] ],
    ]

    ROOT:
    {
        "rulesets": [ RULESET[,RULESET[,...]]  ],
        "version": "1.0.0"
    }

In plain english, the general idea is that each oomd config one or more
RULESETs.  Each RULESET has a set of DETECTOR_GROUPs and a set of ACTIONs. Each
DETECTOR_GROUP has a set of DETECTORs. Both DETECTORs and ACTIONs are PLUGIN
types. That means _everything_ is a plugin in oomd. The rules on how a
conforming config is evaulated at runtime are described in the next section.

## Runtime evaulation rules

* Every plugin must return CONTINUE or STOP.
  * CONTINUE
    * For DETECTORs, continue evaluating DETECTORs in the current DETECTOR_GROUP
      chain
    * For ACTIONs, continue executing the current ACTION chain
  * STOP
    * For DETECTORs, abort evaluation of the current DETECTOR_GROUP chain
    * For ACTIONs, abort execution of the current ACTION chain

* DETECTOR_GROUPs evaluate true if and only if all DETECTORs in the chain
  return CONTINUE

* For each RULESET, if _any_ DETECTOR_GROUP fires, the associated ACTION chain
  will begin execution

## Example

This example uses the JSON front end. At time of writing (11/20/18), JSON
is the only supported config front end. The config compiler has been designed
with extensibility in mind as well. It would not be difficult to add another
config front end.

    {
        "rulesets": [
            {
                "name": "memory pressure protection",
                "detectors": [
                    [
                        "workload is under pressure and system is under a lot of pressure",
                        [
                            "pressure_rising_beyond",
                            "cgroup=workload.slice",
                            "resource=memory",
                            "threshold=5",
                            "duration=15"
                        ],
                        [
                            "pressure_rising_beyond",
                            "cgroup=system.slice",
                            "resource=memory",
                            "threshold=40",
                            "duration=15"
                        ]
                    ],
                    [
                        "system is under a lot of pressure",
                        [
                            "pressure_rising_beyond",
                            "cgroup=system.slice",
                            "resource=memory",
                            "threshold=80",
                            "duration=30"
                        ]
                    ]
                ],
                "actions": [
                    [
                        "kill_by_memory_size_or_growth",
                        "cgroup=system.slice/*"
                    ]
                ]
            },
            {
                "name": "low swap protection",
                "detectors": [
                    [
                        "swap is running low",
                        [
                            "swap_free",
                            "threshold_pct=15"
                        ]
                    ]
                ],
                "actions": [
                    [
                        "kill_by_swap_usage",
                        "cgroup=system.slice/*,workload.slice/workload-wdb.slice/*,workload.slice/workload-tw.slice/*"
                    ]
                ]
            }
        ],
        "version": "1.0.0"
    }

This config, in english, says the following:

* If the workload is under a memory pressure AND the system is under a
  moderate amount of pressure, kill a memory hog in the system

* If the systems is under a lot of memory pressure, kill a memory hog in
  the system

* If the system is running low on swap (this can cause pathological conditions),
  kill the cgroup using the most swap across the system and workloads.
