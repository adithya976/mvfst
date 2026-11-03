/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/congestion_control/test/Utils.h>

using namespace testing;

namespace quic::test {

namespace {

constexpr uint64_t kStartCwnd = 100000;
// float rounding in "cwnd * factor" can be off by a byte or two
constexpr double kCwndTolerance = 2.0;

// An ack of a single packet, optionally carrying a cumulative CE count.
AckEvent makeEcnAck(
    uint64_t ceCount,
    TimePoint sentTime,
    TimePoint ackTime,
    PacketNum pn = 1) {
  auto ack = makeAck(pn, 1000, ackTime, sentTime);
  ack.ecnCECount = ceCount;
  return ack;
}

} // namespace

class CubicEcnTest : public Test {
 public:
  void SetUp() override {
    conn_.ecnState = ECNState::ValidatedECN;
    conn_.transportSettings.ccaConfig.cubicEcnReductionFactor =
        kCubicAbeReductionFactor;
    // Plenty of bytes in flight so the test wrapper never underflows.
    conn_.lossState.inflightBytes = 10'000'000;
  }

  // A Cubic in Steady state with cwnd == ssthresh == kStartCwnd.
  std::unique_ptr<Cubic> makeSteadyCubic(uint64_t cwnd = kStartCwnd) {
    auto cubic = std::make_unique<Cubic>(conn_);
    cubic->handoff(cwnd, cwnd);
    return cubic;
  }

  void processEvent(
      Cubic& cubic,
      Optional<AckEvent> ack,
      Optional<LossEvent> loss = std::nullopt) {
    const auto numSpurious = ack ? ack->numPacketsSpuriouslyAcked : 0;
    conn_.outstandings.declaredLostCount -= numSpurious;
    if (loss) {
      conn_.outstandings.declaredLostCount += loss->lostPackets;
    }
    onPacketAckOrLossWrapper(&conn_, &cubic, std::move(ack), std::move(loss));
  }

  LossEvent makeLoss(PacketNum pn, TimePoint sentTime) {
    auto packet = makeTestingWritePacket(pn, 1000, 1000 * (pn + 1), sentTime);
    LossEvent loss;
    loss.addLostPacket(packet);
    return loss;
  }

  uint64_t ssthresh(const Cubic& cubic) {
    CongestionControllerStats stats{};
    cubic.getStats(stats);
    return stats.cubicStats.ssthresh;
  }

  QuicConnectionStateBase conn_{QuicNodeType::Client};
};

// 1. An ECN-CE mark in Steady state backs off by the ABE factor (0.85).
TEST_F(CubicEcnTest, AbeReductionInSteady) {
  auto cubic = makeSteadyCubic();
  const auto now = Clock::now();
  processEvent(*cubic, makeEcnAck(1, now - 10ms, now));

  EXPECT_NEAR(cubic->getCongestionWindow(), kStartCwnd * 0.85, kCwndTolerance);
  EXPECT_EQ(ssthresh(*cubic), cubic->getCongestionWindow());
  EXPECT_EQ(CubicStates::FastRecovery, cubic->state());
}

// 2. With beta_ecn == beta_loss (classic ECN) an ECN event is exactly a loss.
TEST_F(CubicEcnTest, ClassicEcnMatchesLoss) {
  conn_.transportSettings.ccaConfig.cubicEcnReductionFactor =
      kDefaultCubicReductionFactor;
  auto ecnCubic = makeSteadyCubic();
  const auto now = Clock::now();
  processEvent(*ecnCubic, makeEcnAck(1, now - 10ms, now));

  auto lossCubic = makeSteadyCubic();
  processEvent(*lossCubic, std::nullopt, makeLoss(0, now - 10ms));

  EXPECT_EQ(ecnCubic->getCongestionWindow(), lossCubic->getCongestionWindow());
  EXPECT_EQ(ssthresh(*ecnCubic), ssthresh(*lossCubic));
  EXPECT_EQ(ecnCubic->state(), lossCubic->state());
  EXPECT_NEAR(
      ecnCubic->getCongestionWindow(), kStartCwnd * 0.7, kCwndTolerance);
}

// 3. Default configuration (-1): CE marks do not reduce cwnd (legacy).
TEST_F(CubicEcnTest, DisabledByDefault) {
  conn_.transportSettings.ccaConfig.cubicEcnReductionFactor = -1.0f;
  auto cubic = makeSteadyCubic();
  const auto now = Clock::now();
  processEvent(*cubic, makeEcnAck(5, now - 10ms, now));

  EXPECT_GE(cubic->getCongestionWindow(), kStartCwnd);
  EXPECT_EQ(CubicStates::Steady, cubic->state());
}

// 4. Loss keeps using beta_loss (0.7) even when ABE is configured.
TEST_F(CubicEcnTest, LossStillUsesLossFactor) {
  auto cubic = makeSteadyCubic();
  processEvent(*cubic, std::nullopt, makeLoss(0, Clock::now() - 10ms));

  EXPECT_NEAR(cubic->getCongestionWindow(), kStartCwnd * 0.7, kCwndTolerance);
  EXPECT_EQ(CubicStates::FastRecovery, cubic->state());
}

// 5. Only a validated classic ECN connection reacts. L4S keeps its own path.
TEST_F(CubicEcnTest, NoReactionUnlessValidatedEcn) {
  for (auto state :
       {ECNState::NotAttempted,
        ECNState::AttemptingECN,
        ECNState::AttemptingL4S,
        ECNState::ValidatedL4S,
        ECNState::FailedValidation}) {
    conn_.ecnState = state;
    auto cubic = makeSteadyCubic();
    const auto now = Clock::now();
    processEvent(*cubic, makeEcnAck(1, now - 10ms, now));
    EXPECT_GE(cubic->getCongestionWindow(), kStartCwnd)
        << "ecnState=" << static_cast<int>(state);
    EXPECT_EQ(CubicStates::Steady, cubic->state())
        << "ecnState=" << static_cast<int>(state);
  }
}

// 6. ABE is not applied in slow start (RFC 8511 section 4): Hystart uses 0.7.
TEST_F(CubicEcnTest, HystartUsesLossFactor) {
  Cubic cubic(conn_);
  ASSERT_EQ(CubicStates::Hystart, cubic.state());
  const auto cwndBefore = cubic.getCongestionWindow();
  const auto now = Clock::now();
  processEvent(cubic, makeEcnAck(1, now - 10ms, now));

  EXPECT_NEAR(cubic.getCongestionWindow(), cwndBefore * 0.7, kCwndTolerance);
  EXPECT_EQ(CubicStates::FastRecovery, cubic.state());
}

// 7. One reduction per congestion event: CE marks for packets sent before the
// recovery began are ignored, a CE for a later packet reduces again.
TEST_F(CubicEcnTest, OncePerCongestionEvent) {
  auto cubic = makeSteadyCubic();
  const auto t0 = Clock::now();
  processEvent(*cubic, makeEcnAck(1, t0 - 10ms, t0, 1));
  const auto afterFirst = cubic->getCongestionWindow();
  EXPECT_NEAR(afterFirst, kStartCwnd * 0.85, kCwndTolerance);

  // Packet sent at t0 (before recovery started): same congestion event.
  processEvent(*cubic, makeEcnAck(2, t0 - 5ms, t0 + 1ms, 2));
  EXPECT_EQ(afterFirst, cubic->getCongestionWindow());

  // Packet sent well after recovery started: a new congestion event.
  processEvent(*cubic, makeEcnAck(3, t0 + 100ms, t0 + 101ms, 3));
  EXPECT_LT(cubic->getCongestionWindow(), afterFirst);
  EXPECT_NEAR(
      cubic->getCongestionWindow(), afterFirst * 0.85, 2 * kCwndTolerance);
}

// 8. Loss and CE on the same ack produce a single reduction, at beta_loss.
TEST_F(CubicEcnTest, LossAndCeOnSameAckReduceOnce) {
  auto cubic = makeSteadyCubic();
  const auto now = Clock::now();
  processEvent(
      *cubic, makeEcnAck(1, now - 10ms, now), makeLoss(0, now - 20ms));

  EXPECT_NEAR(cubic->getCongestionWindow(), kStartCwnd * 0.7, kCwndTolerance);
  EXPECT_EQ(CubicStates::FastRecovery, cubic->state());
}

// 9. CE counts from Initial/Handshake ACKs are ignored (lastCECount_ is a
// single counter, but the counts in ACK frames are per packet number space).
TEST_F(CubicEcnTest, IgnoresNonAppDataSpace) {
  auto cubic = makeSteadyCubic();
  const auto now = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(now)
                 .setAdjustedAckTime(now)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::Handshake)
                 .setLargestAckedPacket(1)
                 .build();
  ack.ackedBytes = 1000;
  ack.largestNewlyAckedPacket = 1;
  OutstandingPacketMetadata opm(
      now - 10ms,
      0,
      1000,
      1000,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  ack.ackedPackets.emplace_back(
      AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setOutstandingPacketMetadata(opm)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());
  ack.largestNewlyAckedPacketSentTime = now - 10ms;
  ack.ecnCECount = 3;
  processEvent(*cubic, std::move(ack));

  EXPECT_GE(cubic->getCongestionWindow(), kStartCwnd);
  EXPECT_EQ(CubicStates::Steady, cubic->state());
}

// 10. A pending spurious-loss undo must not restore a cwnd above an ECN
// reduction that happened after the loss.
TEST_F(CubicEcnTest, SpuriousLossUndoDoesNotCancelEcnReduction) {
  conn_.transportSettings.ccaConfig.enableSpuriousLossRecovery = true;
  auto cubic = makeSteadyCubic();
  const auto t0 = Clock::now();
  processEvent(*cubic, std::nullopt, makeLoss(0, t0 - 10ms));
  const auto afterLoss = cubic->getCongestionWindow();
  EXPECT_NEAR(afterLoss, kStartCwnd * 0.7, kCwndTolerance);

  // New congestion event, signalled by ECN.
  processEvent(*cubic, makeEcnAck(1, t0 + 100ms, t0 + 101ms));
  const auto afterEcn = cubic->getCongestionWindow();
  EXPECT_LT(afterEcn, afterLoss);

  // The earlier loss turns out to be spurious.
  auto spurious = makeEcnAck(1, t0 + 100ms, t0 + 102ms, 2);
  spurious.ackedBytes = 0;
  spurious.numPacketsSpuriouslyAcked = 1;
  spurious.largestNewlyAckedPacket.reset();
  processEvent(*cubic, std::move(spurious));
  EXPECT_EQ(afterEcn, cubic->getCongestionWindow());
}

// 11. Leaving recovery after an ECN reduction works: the cwnd == ssthresh
// invariant holds and Cubic resumes growing from the reduced window.
TEST_F(CubicEcnTest, ExitsRecoveryAfterEcnReduction) {
  auto cubic = makeSteadyCubic();
  const auto t0 = Clock::now();
  processEvent(*cubic, makeEcnAck(1, t0 - 10ms, t0, 1));
  const auto reduced = cubic->getCongestionWindow();
  ASSERT_EQ(CubicStates::FastRecovery, cubic->state());

  // Same CE count, packet sent after recovery started: recovery ends.
  processEvent(*cubic, makeEcnAck(1, t0 + 100ms, t0 + 200ms, 2));
  EXPECT_EQ(CubicStates::Steady, cubic->state());
  EXPECT_GE(cubic->getCongestionWindow(), reduced);
}

// 12. The reduction never goes below the minimum window.
TEST_F(CubicEcnTest, RespectsMinimumCwnd) {
  const uint64_t minCwnd =
      conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen;
  auto cubic = makeSteadyCubic(minCwnd + 10);
  const auto now = Clock::now();
  processEvent(*cubic, makeEcnAck(1, now - 10ms, now));
  EXPECT_EQ(minCwnd, cubic->getCongestionWindow());
}

} // namespace quic::test