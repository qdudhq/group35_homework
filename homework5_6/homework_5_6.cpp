#include <openfhe/pke/openfhe.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>

using namespace lbcrypto;

int main() {
    // ==================== 1. 参数设置 ====================
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(1 << 16);          // 4096，足够容纳16个槽位
    parameters.SetScalingModSize(50);
    parameters.SetMultiplicativeDepth(10);     // 卷积需要乘法和加法

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    std::cout << "CKKS scheme using ring dimension " << cc->GetRingDimension() << std::endl;
    size_t numSlots = cc->GetRingDimension() / 2;
    std::cout << "Number of slots: " << numSlots << std::endl;

    // ==================== 2. 密钥生成 ====================
    auto keys = cc->KeyGen();

    // 生成旋转密钥（需要旋转的偏移量：1到15）
    std::vector<int> rotIndices;
    for (int i = 1; i < 16; i++) {
        rotIndices.push_back(i);
        rotIndices.push_back(-i);
    }
    cc->EvalRotateKeyGen(keys.secretKey, rotIndices);

    // ==================== 3. 输入数据 ====================
    // 4x4 输入矩阵（行优先展平）
    std::vector<double> input = {
        1,  2,  3,  4,
        5,  6,  7,  8,
        9,  10, 11, 12,
        13, 14, 15, 16
    };

    // 3x3 卷积核（行优先展平）
    std::vector<double> kernel = {
        1, 0, -1,
        1, 0, -1,
        1, 0, -1
    };

    // ==================== 4. 加密 ====================
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(input);
    auto ciphertext = cc->Encrypt(keys.publicKey, ptxt);

    // ==================== 5. 密文卷积（优化版） ====================
    // 利用“打包→旋转→累加”一次完成所有窗口
    // 3x3卷积核在4x4输入上滑动，共有4个窗口，对应输入中9个偏移位置
    // 偏移量（行优先索引）：
    std::vector<int> offsets = {0, 1, 2, 4, 5, 6, 8, 9, 10};
    // 注意：这9个偏移量对应卷积核的9个权重位置，对于所有窗口是相同的。

    int rotation_count_core = 0;  // 只统计卷积计算中的旋转次数

    // 初始化累加密文为0（以第一个权重乘以旋转后的密文作为初始）
    Ciphertext<DCRTPoly> conv_result;
    bool first = true;

    for (int k = 0; k < 9; ++k) {
        int offset = offsets[k];
        double weight = kernel[k];

        Ciphertext<DCRTPoly> rotated;
        if (offset == 0) {
            rotated = ciphertext;  // 不旋转
        } else {
            // 关键修正：使用正偏移（尝试负偏移导致错误）
            rotated = cc->EvalRotate(ciphertext, offset);
            rotation_count_core++;
        }

        // 乘以权重
        auto weighted = cc->EvalMult(rotated, weight);

        // 累加
        if (first) {
            conv_result = weighted;
            first = false;
        } else {
            conv_result = cc->EvalAdd(conv_result, weighted);
        }
    }

    // 此时 conv_result 的槽位 0~3 分别存放四个窗口的卷积结果
    // 因为四个窗口的对应偏移元素在旋转后都会对齐到对应槽位（0~3）
    // 注意：偏移0的元素本来就分布在槽位0,1,2,3（对应四个窗口的左上角）
    // 旋转后，所有窗口的相同相对位置元素会累加在相同槽位。

    std::cout << "\n=== 旋转次数统计（卷积核心） ===" << std::endl;
    std::cout << "卷积计算中的旋转次数: " << rotation_count_core << std::endl;
    std::cout << "理论最小值: 8 (因为9个偏移量中有1个偏移0无需旋转)" << std::endl;

    // ==================== 6. 解密验证 ====================
    Plaintext result_ptxt;
    cc->Decrypt(keys.secretKey, conv_result, &result_ptxt);
    result_ptxt->SetLength(4);
    std::vector<std::complex<double>> decrypted_complex = result_ptxt->GetCKKSPackedValue();
    std::vector<double> decrypted(4);
    for (size_t i = 0; i < 4; ++i) {
        decrypted[i] = decrypted_complex[i].real();
    }

    // ==================== 7. 明文卷积验证 ====================
    // 窗口定义（四个窗口的输入索引）
    std::vector<std::vector<int>> windows = {
        {0, 1, 2, 4, 5, 6, 8, 9, 10},
        {1, 2, 3, 5, 6, 7, 9, 10, 11},
        {4, 5, 6, 8, 9, 10, 12, 13, 14},
        {5, 6, 7, 9, 10, 11, 13, 14, 15}
    };
    std::vector<double> expected(4, 0.0);
    for (int win = 0; win < 4; ++win) {
        double sum = 0.0;
        for (int k = 0; k < 9; ++k) {
            sum += input[windows[win][k]] * kernel[k];
        }
        expected[win] = sum;
    }

    // ==================== 8. 输出结果 ====================
    std::cout << "\n=== 卷积结果 ===" << std::endl;
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "窗口位置\t明文结果\t密文解密结果\t误差" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    for (int i = 0; i < 4; ++i) {
        double error = std::abs(expected[i] - decrypted[i]);
        std::cout << "  (" << (i/2) << "," << (i%2) << ")\t"
                  << expected[i] << "\t"
                  << decrypted[i] << "\t"
                  << error << std::endl;
    }

    // ==================== 9. 验证 ====================
    bool success = true;
    for (int i = 0; i < 4; ++i) {
        if (std::abs(expected[i] - decrypted[i]) > 1e-5) {
            success = false;
            break;
        }
    }

    std::cout << "\n=== 验证结果 ===" << std::endl;
    if (success) {
        std::cout << "✓ 验证通过！密文卷积结果与明文卷积结果一致（误差 < 1e-5）" << std::endl;
    } else {
        std::cout << "✗ 验证失败，请检查实现" << std::endl;
    }

    // ==================== 10. 验证 ====================
    bool success = true;
    for (int i = 0; i < 4; i++) {
        if (std::abs(expected[i] - decrypted[i]) > 1e-5) {
            success = false;
            break;
        }
    }

    std::cout << "\n=== 验证结果 ===" << std::endl;
    if (success) {
        std::cout << "✓ 验证通过！密文卷积结果与明文卷积结果一致（误差 < 1e-5）" << std::endl;
    } else {
        std::cout << "✗ 验证失败，请检查实现" << std::endl;
    }

    return 0;
}