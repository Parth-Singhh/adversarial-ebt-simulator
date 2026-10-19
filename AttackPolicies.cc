#include "AttackModel.h"

#include <algorithm>
#include <cstdint>
#include <memory>

using namespace omnetpp;

namespace {

class HonestPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext&) const override
    {
        return AttackOutcome{};
    }
};

class DropAllPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext&) const override
    {
        AttackOutcome out;

        out.drop = true;
        out.reason = "drop_all";
        out.attackFlags |= ATTACK_FLAG_DROP;

        return out;
    }
};

class ProbabilisticForwardPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext& ctx) const override
    {
        AttackOutcome out;

        double p =
            std::max(
                0.0,
                std::min(
                    1.0,
                    ctx.config.forwardProb
                )
            );

        if (uniform(
                getEnvir()->getRNG(0),
                0,
                1
            ) > p) {

            out.drop = true;
            out.reason = "probabilistic_drop";
            out.attackFlags |= ATTACK_FLAG_DROP;
        }
        else {
            out.reason = "probabilistic_forward";
        }

        return out;
    }
};

class DelayPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext& ctx) const override
    {
        AttackOutcome out;

        if (ctx.config.maxExtraDelay >
            SIMTIME_ZERO) {

            out.extraDelay =
                uniform(
                    getEnvir()->getRNG(0),
                    SIMTIME_ZERO,
                    ctx.config.maxExtraDelay
                );
        }

        out.reason = "delay_forward";
        out.attackFlags |= ATTACK_FLAG_DELAY;

        return out;
    }
};

class SelectiveForwardPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext& ctx) const override
    {
        AttackOutcome out;

        double fraction =
            std::max(
                0.0,
                std::min(
                    1.0,
                    ctx.config.selectiveTargetFraction
                )
            );

        /*
         * Deterministic target selection.
         *
         * The previous implementation performed the hash arithmetic
         * using signed int. The multiplier below is large enough that
         * ordinary node IDs can overflow a signed int, which is
         * undefined behavior in C++.
         *
         * uint32_t gives us deliberate modulo-2^32 arithmetic instead.
         */
        uint32_t hash =
            static_cast<uint32_t>(
                ctx.nodeId
            );

        hash =
            hash * 1103515245u
            + 12345u *
              static_cast<uint32_t>(
                  ctx.neighborId
              );

        hash +=
            static_cast<uint32_t>(
                ctx.broadcastSeq
            );

        const uint32_t bucket =
            hash & 1023u;

        const double normalized =
            bucket / 1023.0;

        if (normalized > fraction) {

            out.drop = true;
            out.reason = "selective_drop";

            out.attackFlags |=
                ATTACK_FLAG_SELECTIVE |
                ATTACK_FLAG_DROP;
        }
        else {

            out.reason = "selective_forward";

            out.attackFlags |=
                ATTACK_FLAG_SELECTIVE;
        }

        return out;
    }
};

class IsolationPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext& ctx) const override
    {
        AttackOutcome out;

        const std::string& mode =
            ctx.config.isolationMode;

        bool isolate = false;

        if (mode == "source") {

            isolate =
                (ctx.neighborId ==
                 ctx.sourceId);
        }
        else if (mode == "explicit") {

            isolate =
                ctx.config.isolatedPeers.count(
                    ctx.neighborId
                ) > 0;
        }
        else if (mode == "component") {

            isolate =
                ctx.config.isolatedPeers.empty() ||
                ctx.config.isolatedPeers.count(
                    ctx.neighborId
                ) > 0;
        }

        if (isolate) {

            out.drop = true;
            out.reason = "isolation_drop";

            out.attackFlags |=
                ATTACK_FLAG_ISOLATION |
                ATTACK_FLAG_DROP;
        }
        else {

            out.reason = "isolation_forward";

            out.attackFlags |=
                ATTACK_FLAG_ISOLATION;
        }

        return out;
    }
};

class FloodDuplicatesPolicy : public AttackPolicy
{
  public:
    AttackOutcome decide(const AttackContext&) const override
    {
        AttackOutcome out;

        out.duplicateBurst = 2;
        out.reason = "flood_duplicates";

        return out;
    }
};

} // namespace


std::unique_ptr<AttackPolicy>
AttackModel::createPolicy(AttackType type)
{
    switch (type) {

        case AttackType::DropAll:
            return std::make_unique<
                DropAllPolicy
            >();

        case AttackType::ProbabilisticForward:
            return std::make_unique<
                ProbabilisticForwardPolicy
            >();

        case AttackType::Delay:
            return std::make_unique<
                DelayPolicy
            >();

        case AttackType::SelectiveForward:
            return std::make_unique<
                SelectiveForwardPolicy
            >();

        case AttackType::Isolation:
            return std::make_unique<
                IsolationPolicy
            >();

        case AttackType::FloodDuplicates:
            return std::make_unique<
                FloodDuplicatesPolicy
            >();

        default:
            return std::make_unique<
                HonestPolicy
            >();
    }
}