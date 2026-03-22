/*
 * FDP-aware custom mutator for fuzz_pool.
 *
 * Input layout (FDP reads from END of buffer):
 *   byte[size-1]  = n_pre    (0..15)
 *   byte[size-2]  = do_crash (0/1)
 *   byte[size-3]  = n_lose   (0..MAX_LOSE_WRITES)
 *   byte[size-4]  = n_post   (0..7)
 *   per message (4 bytes, from end toward start):
 *     src-1, vtype, slot, cand
 *
 * Mutations (chosen by rand):
 *   0. FlipVtype      — change vtype of a random message (bias toward interesting pairs)
 *   1. FlipSlot       — change slot of a random message
 *   2. FlipCand       — change cand of a random message (amnesia trigger)
 *   3. FlipCrash      — toggle do_crash
 *   4. IncrNLose      — increment n_lose (lose more WAL entries)
 *   5. AddMessage     — insert a new message before or after crash
 *   6. RemoveMessage  — remove a random message
 *   7. DupWithDiffCand — duplicate a message with cand+1 (amnesia setup)
 *   8. MirrorPrePost  — copy a pre-crash message to post-crash with different cand
 *   9. SkipAfterNotar — append SkipVote×3 on same slot as the first Propose found
 */

#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

static constexpr uint8_t MAX_SLOT         = 15;
static constexpr uint8_t N_CAND_SEEDS     = 4;
static constexpr uint8_t MAX_VALIDATORS   = 3;  // src-1 range: 0..2
static constexpr uint8_t MAX_VTYPE        = 7;
static constexpr uint8_t MAX_LOSE_WRITES  = 10;
static constexpr uint8_t MAX_N_PRE        = 15;
static constexpr uint8_t MAX_N_POST       = 7;
static constexpr size_t  HDR_SIZE         = 4;   // n_pre, do_crash, n_lose, n_post
static constexpr size_t  MSG_SIZE         = 4;   // src-1, vtype, slot, cand

// ── Parsed representation ────────────────────────────────────────────────────

struct Msg { uint8_t src, vtype, slot, cand; };

struct Input {
  uint8_t n_pre, do_crash, n_lose, n_post;
  Msg msgs[23];   // max n_pre(15) + n_post(7) = 22
  uint8_t n_msgs;
};

// Decode buffer → Input. Returns false if too short.
static bool decode(const uint8_t* data, size_t size, Input& inp) {
  if (size < HDR_SIZE) return false;
  inp.n_pre    = data[size - 1] % (MAX_N_PRE  + 1);
  inp.do_crash = data[size - 2] & 1;
  inp.n_lose   = data[size - 3] % (MAX_LOSE_WRITES + 1);
  inp.n_post   = data[size - 4] % (MAX_N_POST + 1);
  inp.n_msgs   = inp.n_pre + inp.n_post;
  if (size < HDR_SIZE + (size_t)inp.n_msgs * MSG_SIZE) {
    // not enough bytes — clamp
    inp.n_msgs = static_cast<uint8_t>((size - HDR_SIZE) / MSG_SIZE);
    if (inp.n_msgs < inp.n_pre) { inp.n_pre = inp.n_msgs; inp.n_post = 0; }
    else inp.n_post = inp.n_msgs - inp.n_pre;
  }
  // messages are laid out from end toward start, starting at byte[size-5]
  size_t base = size - HDR_SIZE;
  for (int i = 0; i < inp.n_msgs; i++) {
    size_t off = base - (i + 1) * MSG_SIZE;
    inp.msgs[i].src   = (data[off]     % MAX_VALIDATORS) + 1;  // 1..3
    inp.msgs[i].vtype =  data[off + 1] % (MAX_VTYPE + 1);
    inp.msgs[i].slot  =  data[off + 2] % (MAX_SLOT  + 1);
    inp.msgs[i].cand  =  data[off + 3] % N_CAND_SEEDS;
  }
  return true;
}

// Encode Input → buffer. Returns encoded size, or 0 if max_size too small.
static size_t encode(const Input& inp, uint8_t* out, size_t max_size) {
  size_t need = HDR_SIZE + (size_t)inp.n_msgs * MSG_SIZE;
  if (need > max_size) return 0;
  // messages from end toward start
  size_t base = need - HDR_SIZE;
  for (int i = 0; i < inp.n_msgs; i++) {
    size_t off = base - (i + 1) * MSG_SIZE;
    out[off]     = (inp.msgs[i].src - 1) & 0xFF;
    out[off + 1] =  inp.msgs[i].vtype;
    out[off + 2] =  inp.msgs[i].slot;
    out[off + 3] =  inp.msgs[i].cand;
  }
  out[need - 4] = inp.n_post;
  out[need - 3] = inp.n_lose;
  out[need - 2] = inp.do_crash;
  out[need - 1] = inp.n_pre;
  return need;
}

static uint8_t rand_src()   { return static_cast<uint8_t>((rand() % MAX_VALIDATORS) + 1); }
static uint8_t rand_vtype() { return static_cast<uint8_t>(rand() % (MAX_VTYPE + 1)); }
static uint8_t rand_slot()  { return static_cast<uint8_t>(rand() % (MAX_SLOT + 1)); }
static uint8_t rand_cand()  { return static_cast<uint8_t>(rand() % N_CAND_SEEDS); }

// ── Custom mutator entry point ────────────────────────────────────────────────

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                           size_t max_size, unsigned int seed) {
  srand(seed);

  Input inp{};
  if (!decode(data, size, inp) || inp.n_msgs == 0) {
    // Fallback: let libFuzzer do its thing, but ensure minimal valid structure.
    if (max_size < HDR_SIZE) return size;
    inp.n_pre = 1; inp.do_crash = 0; inp.n_lose = 0; inp.n_post = 0;
    inp.n_msgs = 1;
    inp.msgs[0] = {1, 3, 0, 0};  // Propose(src=1, slot=0, cand=0)
    size_t s = encode(inp, data, max_size);
    return s ? s : size;
  }

  int op = rand() % 10;
  switch (op) {
    case 0: {  // FlipVtype — bias toward interesting vtypes
      int i = rand() % inp.n_msgs;
      static const uint8_t interesting[] = {0, 1, 2, 3, 7};
      inp.msgs[i].vtype = interesting[rand() % 5];
      break;
    }
    case 1: {  // FlipSlot
      int i = rand() % inp.n_msgs;
      inp.msgs[i].slot = rand_slot();
      break;
    }
    case 2: {  // FlipCand — key for amnesia
      int i = rand() % inp.n_msgs;
      inp.msgs[i].cand = rand_cand();
      break;
    }
    case 3: {  // FlipCrash
      inp.do_crash ^= 1;
      break;
    }
    case 4: {  // IncrNLose — lose more WAL entries
      if (inp.n_lose < MAX_LOSE_WRITES) inp.n_lose++;
      break;
    }
    case 5: {  // AddMessage
      if (inp.n_msgs >= 22) break;
      Msg m{rand_src(), rand_vtype(), rand_slot(), rand_cand()};
      // insert at random position
      int pos = rand() % (inp.n_msgs + 1);
      for (int i = inp.n_msgs; i > pos; i--) inp.msgs[i] = inp.msgs[i-1];
      inp.msgs[pos] = m;
      inp.n_msgs++;
      // assign to pre or post
      if (pos < inp.n_pre) inp.n_pre++;
      else if (inp.n_post < MAX_N_POST) inp.n_post++;
      else inp.n_pre++;
      break;
    }
    case 6: {  // RemoveMessage
      if (inp.n_msgs == 0) break;
      int pos = rand() % inp.n_msgs;
      for (int i = pos; i < inp.n_msgs - 1; i++) inp.msgs[i] = inp.msgs[i+1];
      inp.n_msgs--;
      if (pos < inp.n_pre && inp.n_pre > 0) inp.n_pre--;
      else if (inp.n_post > 0) inp.n_post--;
      break;
    }
    case 7: {  // DupWithDiffCand — amnesia setup: same slot, different cand
      int i = rand() % inp.n_msgs;
      if (inp.n_msgs >= 22) break;
      Msg dup = inp.msgs[i];
      dup.cand = (dup.cand + 1) % N_CAND_SEEDS;
      // insert duplicate right after original, in post-crash section
      int post_start = inp.n_pre;
      int ins = post_start + (inp.n_post > 0 ? rand() % inp.n_post : 0);
      for (int j = inp.n_msgs; j > ins; j--) inp.msgs[j] = inp.msgs[j-1];
      inp.msgs[ins] = dup;
      inp.n_msgs++;
      if (inp.n_post < MAX_N_POST) inp.n_post++;
      inp.do_crash = 1;
      if (inp.n_lose == 0) inp.n_lose = 1;
      break;
    }
    case 8: {  // MirrorPrePost — copy pre-crash msg to post-crash with different cand
      if (inp.n_pre == 0 || inp.n_post >= MAX_N_POST || inp.n_msgs >= 22) break;
      Msg m = inp.msgs[rand() % inp.n_pre];
      m.cand = (m.cand + 1) % N_CAND_SEEDS;
      inp.msgs[inp.n_msgs] = m;
      inp.n_msgs++;
      inp.n_post++;
      inp.do_crash = 1;
      if (inp.n_lose == 0) inp.n_lose = 1;
      break;
    }
    case 9: {  // SkipAfterNotar — add SkipVote×3 on same slot as first Propose found
      uint8_t target_slot = rand_slot();
      for (int i = 0; i < inp.n_pre; i++) {
        if (inp.msgs[i].vtype == 3) { target_slot = inp.msgs[i].slot; break; }
      }
      // add 3 SkipVotes in post-crash
      for (int s = 1; s <= 3 && inp.n_msgs < 22 && inp.n_post < MAX_N_POST; s++) {
        inp.msgs[inp.n_msgs] = {static_cast<uint8_t>(s), 1, target_slot, 0};
        inp.n_msgs++;
        inp.n_post++;
      }
      inp.do_crash = 1;
      if (inp.n_lose == 0) inp.n_lose = 1;
      break;
    }
  }

  size_t s = encode(inp, data, max_size);
  return s ? s : LLVMFuzzerMutate(data, size, max_size);
}
