#include "demo_vote_counter.h"

void print_help() {
  printf("Takes one parameter, the number of candidates in the election\n");
}

bool DemoVoteCounter::verify_vote(unsigned int vote_id) {
  Gate* input_zero = new Gate(InputLiteral, false, sec);
  Gate* input_one = new Gate(InputLiteral, true, sec);

  Gate* input;
  unsigned long int w_length = log2(num_candidates);
  unsigned long int p_length = pow(2, w_length);
  Gate* temp_and;
  Gate*** p = new Gate**[num_candidates+1];
  for (unsigned long int i = 0; i < num_candidates+1; i++) { //row
	p[i] = new Gate*[p_length+1];
	p[i][0] = input_one;
	if (i > 0) {
	  input = new Gate(Input, vote_id*num_candidates + i-1, sec);
	}
	for (unsigned int j = 1; j < p_length+1; j++) { //col
	  if (i == 0) {
		p[0][j] = input_zero;
	  } else {
		temp_and = new Gate(And, p[i-1][j-1], input, sec);
		p[i][j] = new Gate(Xor, temp_and, p[i-1][j], sec);
	  }
	}
  }

  Gate* output;
  std::vector<Gate*> output_gates;
  for (unsigned long int i = p_length; i > 0; i >>= 1) {
	output = new Gate(Output, p[num_candidates][i], sec);
	output_gates.push_back(output);
  }

  CipherBit** encrypted_results = fh->evaluate(output_gates, votes, pk);
  bool* decrypted_results = fh->decrypt_bit_vector(sk, encrypted_results, w_length+1);

  for (unsigned int i = 0; i < w_length; i++) {
	if (decrypted_results[i]) {
	  printf("%u\n", decrypted_results[i]);
	  return false;
	}
  }
	
  return decrypted_results[w_length];
}

DemoVoteCounter::DemoVoteCounter(unsigned int num_candidates) : num_candidates(num_candidates) {
  sec = new SecuritySettings(4);
  fh = new FullyHomomorphic(sec);
  fh->key_gen(sk, pk);
}

void DemoVoteCounter::get_votes() {
  int scan_result;
  unsigned int vote;
  num_votes = 0;
  char temp_char;
  std::vector<CipherBit*> encrypted_votes_vector;
  CipherBit* encrypted_bit;
  while (true) {
	printf("Please enter a vote (1-%u), or 0 to terminate: ", num_candidates);
	scan_result = scanf("%u", &vote);
	if (scan_result != 1 || vote > num_candidates) {
	  printf("Invalid vote, please try again...\n");
	  while ((temp_char = getchar()) != '\n');
	  continue;
	}
	if (vote == 0) {
	  break;
	}
	for (unsigned int i = 0; i < num_candidates; i++) {
	  encrypted_bit = new CipherBit;
	  fh->encrypt_bit(*encrypted_bit, pk, i == vote-1);
	  fh->print_cipher_bit(*encrypted_bit);
	  encrypted_votes_vector.push_back(encrypted_bit);
	}
	printf("\n");
	num_votes++;
  }

  votes = new CipherBit*[encrypted_votes_vector.size()];
  for (unsigned int i = 0; i < encrypted_votes_vector.size(); i++) {
	votes[i] = encrypted_votes_vector[i];
  }
}

void DemoVoteCounter::verify_votes() {
  printf("Verifying votes\n");
  bool failed = false;
  for (unsigned int i = 0; i < num_votes; i++) {
	if (!verify_vote(i)) {
	  printf("Vote %u failed to verify!\n", i+1);
	  failed = true;
	}
  }

  if (!failed) {
	printf("All votes verified\n");
  }
}

void DemoVoteCounter::count_votes() {
  printf("Counting votes\n");
  Gate* input_zero = new Gate(InputLiteral, false, sec);
  Gate* input_one = new Gate(InputLiteral, true, sec);

  Gate* input;
  unsigned long int w_length = log2(num_votes);
  unsigned long int p_length = pow(2, w_length);
  Gate* temp_and;
  Gate*** candidate_total = new Gate**[num_candidates];
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
	Gate*** p = new Gate**[num_votes+1];
	for (unsigned long int i = 0; i < num_votes+1; i++) { //row
	  p[i] = new Gate*[p_length+1];
	  p[i][0] = input_one;
	  if (i > 0) {
		input = new Gate(Input, (i-1)*num_candidates + candidate, sec);
	  }
	  for (unsigned int j = 1; j < p_length+1; j++) { //col
		if (i == 0) {
		  p[0][j] = input_zero;
		} else {
		  temp_and = new Gate(And, p[i-1][j-1], input, sec);
		  p[i][j] = new Gate(Xor, temp_and, p[i-1][j], sec);
		}
	  }
	}
	candidate_total[candidate] = new Gate*[w_length+1];
	int cur_index = 0;
	for (unsigned long int i = p_length; i > 0; i >>= 1) {
	  candidate_total[candidate][cur_index++] = p[num_votes][i];
	}
  }

  Gate* output;
  std::vector<Gate*> output_gates;
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
	for (unsigned long int i = 0; i < w_length+1; i++) {
	  output = new Gate(Output, candidate_total[candidate][i], sec);
	  output_gates.push_back(output);
	}
  }

  CipherBit** encrypted_results = fh->evaluate(output_gates, votes, pk);
  bool* decrypted_results = fh->decrypt_bit_vector(sk, encrypted_results, num_candidates*(w_length+1));

  textcolor(BRIGHT, RED);
  for (unsigned int candidate = 0; candidate < num_candidates; candidate++) {
	for (unsigned int i = 0; i < w_length+1; i++) {
	  printf("%u ", decrypted_results[candidate*(w_length+1) + i]);
	}
	printf("\n");
  }
  resettextcolor();
}

int main(int argc, char** argv) {
  if (argc != 2) {
	print_help();
	exit(1);
  }

  unsigned int num_candidates = atoi(argv[1]);

  DemoVoteCounter demo(num_candidates);
  demo.get_votes();
  demo.verify_votes();
  demo.count_votes();

}
