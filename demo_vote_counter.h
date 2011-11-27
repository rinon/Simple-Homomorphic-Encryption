#include "fully_homomorphic.h"

class DemoVoteCounter {
 private:
  SecuritySettings* sec;
  unsigned int num_candidates;
  CipherBit** votes;
  FullyHomomorphic* fh;
  bool verify_vote(unsigned int vote_id);
  PrivateKey sk;
  PublicKey pk;
  unsigned int num_votes;
 public:
  DemoVoteCounter(unsigned int num_candidates);
  void get_votes();
  void verify_votes();
  void count_votes();
};
