#include <cuda_runtime.h>
#include "phantom.h"
#include "boot/Bootstrapper.cuh"
#include <vector>
#include <cmath>
#include <random>
#include <memory>
#include <tuple>

using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;
using namespace std;

std::vector<complex<double>> generate_random_vector(size_t size) {
    std::vector<complex<double>> result(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < size; ++i) {
        result[i] = complex<double>(dis(gen), dis(gen));
    }
    return result;
}
std::tuple<double, double, size_t> calculateErrorStats(vector<complex<double>> output_vector, vector<complex<double>> standard_vector) {
    if(output_vector.size() != standard_vector.size()){
        throw std::invalid_argument("Input vectors must have the same size");
    }
    if(output_vector.empty()){
        return std::make_tuple(0.0, 0.0, 0);
    }
    double sumAbsError = 0.0;
    double maxError = 0.0;
    size_t maxError_index = 0;
    for(size_t i = 0; i < output_vector.size(); i++){
        double error = abs(output_vector[i] - standard_vector[i]);
        sumAbsError += error;
        if (maxError < error){
            maxError = error;
            maxError_index = i;
        }
    }
    sumAbsError /= output_vector.size();
    return std::make_tuple(sumAbsError, maxError, maxError_index);
}

void main(){
    size_t poly_modulus_degree = 8192;
    const vector<int>& coeff_modulus = {60, 40, 40, 60};
    double scale = pow(2.0, 40);
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(phantom::arith::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));

    PhantomContext context(parms);
    PhantomCKKSEncoder encoder(context);
    PhantomSecretKey secret_key(context);
    PhantomPublicKey public_key = secret_key.gen_publickey(context);
    PhantomRelinKey relin_keys = secret_key.gen_relinkey(context);
    PhantomGaloisKey galois_keys = secret_key.create_galois_keys(context);

    CKKSEvaluator ckks_evaluator(&context, &public_key, &secret_key, &encoder, &relin_keys, &galois_keys, scale);

    int slots = ckks_evaluator.encoder.slot_count();
    vector<complex<double>> input1_vector = generate_random_vector(slots);
    vector<complex<double>> input2_vector = generate_random_vector(slots);
    vector<complex<double>> input3_vector = generate_random_vector(slots);

    PhantomPlaintext plain1, plain2, plain3;
    ckks_evaluator.encoder.encode(input1_vector, scale, plain1);
    ckks_evaluator.encoder.encode(input2_vector, scale, plain2);
    ckks_evaluator.encoder.encode(input3_vector, scale, plain3);

    //add
    PhantomCiphertext cipher1_add, cipher2_add, dest_add;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_add);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_add);
    vector<PhantomCiphertext> babyct(3, PhantomCiphertext());
    for (int i = 0; i < 3; i++){
        babyct[i] = dest_add;
    }
    cout <<  "ok" << endl;
}
