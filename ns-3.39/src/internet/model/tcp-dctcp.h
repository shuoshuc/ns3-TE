/*
 * Copyright (c) 2017 NITK Surathkal
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Shravya K.S. <shravya.ks0@gmail.com>
 *
 */

#ifndef TCP_DCTCP_H
#define TCP_DCTCP_H

#include "ns3/hash.h"
#include "ns3/tcp-congestion-ops.h"
#include "ns3/tcp-linux-reno.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"

namespace ns3
{

/**
 * \ingroup tcp
 *
 * \brief An implementation of DCTCP. This model implements all of the
 * endpoint capabilities mentioned in the DCTCP SIGCOMM paper.
 */

class TcpDctcp : public TcpLinuxReno
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    /**
     * Create an unbound tcp socket.
     */
    TcpDctcp();

    /**
     * \brief Copy constructor
     * \param sock the object to copy
     */
    TcpDctcp(const TcpDctcp& sock);

    /**
     * \brief Destructor
     */
    ~TcpDctcp() override;

    // Documented in base class
    std::string GetName() const override;

    /**
     * \brief Set configuration required by congestion control algorithm,
     *        This method will force DctcpEcn mode and will force usage of
     *        either ECT(0) or ECT(1) (depending on the 'UseEct0' attribute),
     *        despite any other configuration in the base classes.
     *
     * \param tcb internal congestion state
     */
    void Init(Ptr<TcpSocketState> tcb) override;

    /**
     * TracedCallback signature for DCTCP update of congestion state
     *
     * \param [in] bytesAcked Bytes acked in this observation window
     * \param [in] bytesMarked Bytes marked in this observation window
     * \param [in] alpha New alpha (congestion estimate) value
     */
    typedef void (*CongestionEstimateTracedCallback)(uint32_t bytesAcked,
                                                     uint32_t bytesMarked,
                                                     double alpha);

    // Documented in base class
    uint32_t GetSsThresh(Ptr<const TcpSocketState> tcb, uint32_t bytesInFlight) override;
    Ptr<TcpCongestionOps> Fork() override;
    void PktsAcked(Ptr<TcpSocketState> tcb, uint32_t segmentsAcked, const Time& rtt) override;
    void CwndEvent(Ptr<TcpSocketState> tcb, const TcpSocketState::TcpCAEvent_t event) override;

  private:
    /**
     * \brief Changes state of m_ceState to true
     *
     * \param tcb internal congestion state
     */
    void CeState0to1(Ptr<TcpSocketState> tcb);

    /**
     * \brief Changes state of m_ceState to false
     *
     * \param tcb internal congestion state
     */
    void CeState1to0(Ptr<TcpSocketState> tcb);

    /**
     * \brief Updates the value of m_delayedAckReserved
     *
     * \param tcb internal congestion state
     * \param event the congestion window event
     */
    void UpdateAckReserved(Ptr<TcpSocketState> tcb, const TcpSocketState::TcpCAEvent_t event);

    /**
     * \brief Resets the value of m_ackedBytesEcn, m_ackedBytesTotal and m_nextSeq
     *
     * \param tcb internal congestion state
     */
    void Reset(Ptr<TcpSocketState> tcb);

    /**
     * \brief Initialize the value of m_alpha
     *
     * \param alpha DCTCP alpha parameter
     */
    void InitializeDctcpAlpha(double alpha);

    // Called once per round-trip to update PLB state for a connection.
    void PlbUpdateState(double cong_ratio);

    // Check whether recent congestion has been persistent enough to warrant a
    // load balancing decision that switches the connection to another path.
    void PlbCheckRehash(Ptr<TcpSocketState>& tcb);

    // Upon RTO, disallow load balancing for a while, to avoid having load
    // balancing decisions switch traffic to a black-holed path that was
    // previously avoided with a rehash() call at RTO time.
    void PlbUpdateStateUponRto();

    uint32_t m_ackedBytesEcn;       //!< Number of acked bytes which are marked
    uint32_t m_ackedBytesTotal;     //!< Total number of acked bytes
    SequenceNumber32 m_priorRcvNxt; //!< Sequence number of the first missing byte in data
    bool m_priorRcvNxtFlag; //!< Variable used in setting the value of m_priorRcvNxt for first time
    double m_alpha;         //!< Parameter used to estimate the amount of network congestion
    SequenceNumber32
        m_nextSeq;      //!< TCP sequence number threshold for beginning a new observation window
    bool m_nextSeqFlag; //!< Variable used in setting the value of m_nextSeq for first time
    bool m_ceState;     //!< DCTCP Congestion Experienced state
    bool m_delayedAckReserved; //!< Delayed Ack state
    double m_g;                //!< Estimation gain
    bool m_useEct0;            //!< Use ECT(0) for ECN codepoint
    bool m_initialized;        //!< Whether DCTCP has been initialized
                               //
    // Below is for PLB.
    uint8_t m_consec_cong_rounds; //!< Consecutive congested rounds
    Time m_pause_until;           //!< When PLB can resume rerouting
    // Number of consecutive congested rounds (RTT) seen after which a rehash
    // can be performed, given there are no packets in flight. This is referred
    // to as M in PLB paper.
    uint8_t m_plb_idle_rehash_rounds = 3;
    // Number of consecutive congested rounds (RTT) seen after which a forced
    // rehash can be performed. Be careful when setting this parameter, as a
    // small value increases the risk of retransmissions. This is referred to
    // as N in PLB paper.
    uint8_t m_plb_rehash_rounds = 3;
    // Time, in seconds, to suspend PLB in event of an RTO.
    uint8_t m_plb_suspend_rto_sec = 60;
    // Fraction of packets marked with congestion over a round (RTT) to tag that
    // round as congested. This is referred to as K in the PLB paper.
    double m_plb_cong_thresh = 0.5;
    // A random number generator.
    Ptr<UniformRandomVariable> m_rand;
    /**
     * \brief Callback pointer for congestion state update
     */
    TracedCallback<uint32_t, uint32_t, double> m_traceCongestionEstimate;
};

} // namespace ns3

#endif /* TCP_DCTCP_H */
