#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <assert.h>

//MILESTONE1

/**
 * Helper function, turns hex values into decimals individually
 * Stole this from the quiz, implemented into next function
 */
uint8_t hex_to_decimal(unsigned char input){
    if(input >= 97 && input <= 102){
        return(input - 87);
    } else if (input >= 65 && input <= 80){
        return(input - 55);
    } else if (input >= 48 && input <= 57){
        return(input - 48);
    } else{
        return -1;
    }
}

/**
 * Takes two characters, returns the decimal value of their 
 * combined value
 */
uint8_t hex_to_byte(unsigned char h1, unsigned char h2){
    uint8_t first = hex_to_decimal(h1);
    uint8_t second = hex_to_decimal(h2);
    return(first << 4 | second);
}

/**
 * Takes a string of hex values and inputs them into an array in pairs
 * such that the array stores complete bytes of hex values
 */
 void hexstr_to_hash(unsigned char hexstr[], unsigned char hash[32]){
    uint8_t hash_idx = 0;
    uint8_t string_idx = 0;
    for(string_idx; string_idx < 64; string_idx+=2){
        uint8_t hex_val = hex_to_byte(hexstr[string_idx], hexstr[string_idx + 1]);
        hash[hash_idx] = hex_val;
        hash_idx++; 
    }
}


//MILESTONE2

const int SHA_LENGTH = 32;

uint8_t check_password(unsigned char password[], unsigned char given_hash[32]){
	uint8_t indicator = 1;
	unsigned char password_hash[SHA_LENGTH];
	SHA256(password, strlen(password), password_hash);

	uint8_t check_password_idx = 0;
	for(check_password_idx = 0; check_password_idx<SHA_LENGTH; check_password_idx++){
		//printf("%x-%x   ", given_hash[check_password_idx], password_hash[check_password_idx]);
		if (given_hash[check_password_idx] != password_hash[check_password_idx]){
			indicator = 0;
		}
	}
	

	return indicator;
}

//MILESTONE3

uint8_t crack_password(unsigned char password[], unsigned char given_hash[]){
	uint8_t match_indicator = 0;
	uint8_t initial_check = check_password(password, given_hash);
	if(initial_check == 1){
		return 1;
	} else{
		unsigned char password_copy[strlen(password)];
		strcpy(password_copy, password);
		uint8_t password_idx = 0;
		for(password_idx = 0; password_idx < strlen(password); password_idx++){
			if(password_copy[password_idx] <= 'z' && password_copy[password_idx] >= 'a'){
				password_copy[password_idx] -= 32;
				uint8_t check = check_password(password_copy, given_hash);

			        //printf("%s%p-%s%p\n", password, password[password_idx], password_copy, password_copy[password_idx]);	
				if(check == 1){
					password[password_idx] = password_copy[password_idx];
					return 1;
				}else{
					password_copy[password_idx] += 32;
				}
			       //printf("%s%p-%s%p\n", password, password[password_idx], password_copy, password_copy[password_idx]);	
			} else if(password_copy[password_idx] <= 'Z' && password_copy[password_idx] >= 'A'){
				password_copy[password_idx] += 32;
				uint8_t check = check_password(password_copy, given_hash);
					
				//printf("%s%p-%s%p\n", password, password[password_idx], password_copy, password_copy[password_idx]);
				if(check == 1){
					password[password_idx] = password_copy[password_idx];
					return 1;
				}else{
					password_copy[password_idx] -= 32;
				}
			}else{
				continue;
			}
			//printf("%p-%p\n", password[password_idx], password_copy[password_idx]);
			//printf("%s-%s\n", password, password_copy);

		}
		return 0;
	}
}




int main(int argc, char** argv){

	int bogo_indicator = 0;

	while(bogo_indicator == 0){


	int r1 = rand() % 93;
	int r2 = rand() % 93;
	int r3 = rand() % 93;
	int r4 = rand() % 93;
	int r5 = rand() % 93;
	int r6 = rand() % 93;

	r1 += 33;
	r2 += 33;
	r3 += 33;
	r4 += 33;
	r5 += 33;
	r6 += 33;

	char test_password[6];
	test_password[0] = r1;
	test_password[1] = r2;
	test_password[2] = r3;
	test_password[3] = r4;
	test_password[4] = r5;
	test_password[5] = r6;

	int test = 0; 
	for(test; test< 6; test++){
		printf("%d"
	}

	unsigned char buff[SHA_LENGTH];
	SHA256(test_password, 6, buff);

	unsigned char in_hash[SHA_LENGTH];
	hexstr_to_hash(argv[1], in_hash);

	crack_password(test_password, in_hash);
	}
	printf("password cracked");

	return 0;


	//LAB TESTING
	 int test = 0; // Set this variable to 1 to run unit tests instead of the entire program

   	 if (test) {
        	assert(hex_to_byte('a', '2') == 162);
        	// ADD MORE TESTS HERE. MAKE SURE TO ADD TESTS THAT FAIL AS WELL TO SEE WHAT HAPPENS!
        
     	   printf("ALL TESTS PASSED!\n");
   	     return 0;
	}

	unsigned char input_hash[SHA_LENGTH];
	hexstr_to_hash(argv[1], input_hash);
	int8_t match_indicator = 0;
	unsigned char input[256];

	while(match_indicator == 0){
	
		fgets(input, 256, stdin);
		input[strcspn(input, "\n")] = 0;

		if(input[0] == 0){
			break;
		}

		match_indicator = crack_password(input, input_hash);
	}
	if(match_indicator == 1){
		printf("Found password: SHA256(%s) = ", input);
		unsigned char print_hash[SHA_LENGTH];
		SHA256(input, strlen(input), print_hash);
		uint8_t print_idx = 0;
		for(print_idx; print_idx< 32; print_idx++){
			printf("%02x", print_hash[print_idx]);
		}
		printf("\n");
	}else{
		printf("No matching password found\n");
	}	



	//All tests for milestones 1-3, commented out for output readability

	/*
	
   	 //printf("%d\n", hex_to_byte('c', '8'));

    	char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
    	unsigned char hash[32];
    	hexstr_to_hash(hexstr, hash);
    	uint8_t print_idx = 0;
    	for(print_idx; print_idx < 32; print_idx++){
        //printf("%d, ", hash[print_idx]);
   
   	 }
  	  //Assert calls for the hex to byte function
    	assert(hex_to_byte('c', '8') == 200);
	assert(hex_to_byte('0', '3') == 3);
	assert(hex_to_byte('0', 'a') == 10);
	assert(hex_to_byte('1', '0') == 16);
  	  //Assert calls for the indices of hash after hexstr_to_hash is called
  	assert(hash[0] == 0xa2);
  	assert(hash[31] == 0xfd);

	//tests for password crack
	
	char test_password[] = "password";
	unsigned char test_password_hash[SHA_LENGTH];
	SHA256(test_password, strlen(test_password), test_password_hash);

	char test_password2[] = "Password";
	unsigned char test_password2_hash[SHA_LENGTH];
	SHA256(test_password2, strlen(test_password2), test_password2_hash);

	char test_password3[] = "passWord";
	unsigned char test_password3_hash[SHA_LENGTH];
	SHA256(test_password3, strlen(test_password3), test_password3_hash);

	//printf("Passwords match? %d\n", check_password(test_password, test_password_hash));
	//printf("Passwords match? %d\n", check_password(test_password, test_password2_hash));

	uint8_t test_password_idx = 0;
	for(test_password_idx = 0; test_password_idx < 32; test_password_idx++){
		//printf("%x,", test_password_hash[test_password_idx]);
	}

	crack_password(test_password, test_password3_hash);
	printf("%s\n", test_password);

	char test_password4[] = "PASSWORd";
	unsigned char test_password4_hash[SHA_LENGTH];
	SHA256(test_password4, strlen(test_password4), test_password4_hash);

	char test_password5[] = "PASSWORD";
	unsigned char test_password5_hash[SHA_LENGTH];
	SHA256(test_password5, strlen(test_password5), test_password5_hash);

	crack_password(test_password5, test_password4_hash);
	printf("%s\n", test_password5);

	crack_password(test_password, test_password5_hash);
	*/



}  
