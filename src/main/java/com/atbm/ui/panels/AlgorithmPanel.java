package com.atbm.ui.panels;

import com.atbm.service.AffineCipherService;
import com.atbm.service.AsymmetricCryptoService;
import com.atbm.service.BlockCipherService;
import com.atbm.service.CaesarCipherService;
import com.atbm.service.DigitalSignatureService;
import com.atbm.service.HashService;
import com.atbm.service.HillCipherService;
import com.atbm.service.MessageDigestHashService;
import com.atbm.service.PaddingMode;
import com.atbm.service.RsaCryptoService;
import com.atbm.service.RsaDigitalSignatureService;
import com.atbm.service.SubstitutionCipherService;
import com.atbm.service.TranspositionCipherService;
import com.atbm.service.VigenereCipherService;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.io.File;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Files;
import java.nio.file.Path;

public class AlgorithmPanel extends JPanel {
    public enum PanelMode {
        SYMMETRIC,
        ASYMMETRIC,
        HASH,
        SIGNATURE
    }

    private static final String CAESAR_ALGORITHM = "Dịch chuyển";
    private static final String SUBSTITUTION_ALGORITHM = "Thay thế";
    private static final String AFFINE_ALGORITHM = "Affine";
    private static final String VIGENERE_ALGORITHM = "Vigenere";
    private static final String BLOWFISH_ALGORITHM = "Blowfish";
    private static final String CAMELLIA_ALGORITHM = "Camellia";
    private static final String HILL_ALGORITHM = "Hill";
    private static final String TRANSPOSITION_ALGORITHM = "Hoán vị";
    private static final String RSA_ALGORITHM = "RSA";

    private final PanelMode mode;
    private final AffineCipherService affineCipherService = new AffineCipherService();
    private final AsymmetricCryptoService asymmetricCryptoService = new RsaCryptoService();
    private final CaesarCipherService caesarCipherService = new CaesarCipherService();
    private final BlockCipherService blockCipherService = new BlockCipherService();
    private final DigitalSignatureService digitalSignatureService = new RsaDigitalSignatureService();
    private final HashService hashService = new MessageDigestHashService();
    private final HillCipherService hillCipherService = new HillCipherService();
    private final SubstitutionCipherService substitutionCipherService = new SubstitutionCipherService();
    private final TranspositionCipherService transpositionCipherService = new TranspositionCipherService();
    private final VigenereCipherService vigenereCipherService = new VigenereCipherService();

    private JComboBox<String> algorithmBox;
    private JCheckBox generateKeyCheckBox;
    private JTextArea keyField;
    private JTextArea publicKeyField;
    private JTextArea privateKeyField;
    private JTextArea signatureField;
    private JComboBox<String> rsaKeyLengthBox;
    private JComboBox<String> paddingModeBox;
    private JTextField keyLengthField;
    private JTextField filePathField;
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JLabel statusLabel;

    public AlgorithmPanel(String title, String description, String[] algorithms, boolean showKeyArea, boolean showKeyLength) {
        this(title, description, algorithms, inferMode(title, algorithms, showKeyArea, showKeyLength));
    }

    public AlgorithmPanel(String title, String description, String[] algorithms, PanelMode mode) {
        this.mode = mode;
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);

        JPanel content = new JPanel(new GridBagLayout());
        content.setBackground(Color.WHITE);
        content.setBorder(BorderFactory.createEmptyBorder(22, 26, 22, 26));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 14, 0);

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 24));
        titleLabel.setForeground(new Color(28, 39, 58));
        content.add(titleLabel, gbc);

        gbc.gridy++;
        JLabel descLabel = new JLabel("<html><body style='width: 900px;'>" + description + "</body></html>");
        descLabel.setFont(new Font("SansSerif", Font.PLAIN, 14));
        descLabel.setForeground(new Color(75, 84, 100));
        content.add(descLabel, gbc);

        gbc.gridy++;
        content.add(createControlCard(algorithms), gbc);

        if (mode == PanelMode.SIGNATURE) {
            gbc.gridy++;
            content.add(createTipCard(), gbc);
        }

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    private static PanelMode inferMode(String title, String[] algorithms, boolean showKeyArea, boolean showKeyLength) {
        if (title != null && title.toLowerCase().contains("hash")) {
            return PanelMode.HASH;
        }
        if (title != null && title.toLowerCase().contains("chữ ký")) {
            return PanelMode.SIGNATURE;
        }
        if (containsAlgorithm(algorithms, RSA_ALGORITHM) && showKeyArea && showKeyLength) {
            return PanelMode.ASYMMETRIC;
        }
        return PanelMode.SYMMETRIC;
    }

    private JComponent createControlCard(String[] algorithms) {
        JPanel card = new JPanel(new GridBagLayout());
        card.setBackground(new Color(247, 249, 252));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(223, 229, 238)),
                BorderFactory.createEmptyBorder(16, 16, 16, 16)
        ));

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(8, 8, 8, 8);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.gridy = 0;

        algorithmBox = new JComboBox<>(algorithms);
        inputArea = createTextArea(8, 60);
        outputArea = createTextArea(8, 60);
        outputArea.setEditable(false);
        outputArea.setBackground(new Color(250, 251, 253));
        outputArea.setBorder(BorderFactory.createLineBorder(new Color(225, 230, 238)));
        statusLabel = new JLabel("Sẵn sàng.");
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));
        statusLabel.setForeground(new Color(68, 79, 99));
        generateKeyCheckBox = new JCheckBox("Tự tạo key nếu chưa nhập key sẵn", true);
        generateKeyCheckBox.setOpaque(false);
        generateKeyCheckBox.setFont(new Font("SansSerif", Font.PLAIN, 14));

        addRow(card, c, "Thuật toán", algorithmBox);

        if (mode == PanelMode.SYMMETRIC) {
            keyField = createTextArea(2, 60);
            keyLengthField = new JTextField(initialSymmetricKeyLength(algorithms));
            addRow(card, c, "Key", wrap(keyField, 60));
            addRow(card, c, "Độ dài key", keyLengthField);
            
            paddingModeBox = new JComboBox<>();
            for (PaddingMode mode : PaddingMode.values()) {
                paddingModeBox.addItem(mode.getDisplayName());
            }
            paddingModeBox.setSelectedItem(PaddingMode.PKCS5.getDisplayName());
            addRow(card, c, "Chế độ padding", paddingModeBox);
            
            addGenerateToggle(card, c);
        } else if (mode == PanelMode.ASYMMETRIC || mode == PanelMode.SIGNATURE) {
            publicKeyField = createTextArea(4, 60);
            privateKeyField = createTextArea(4, 60);
            rsaKeyLengthBox = new JComboBox<>(new String[]{"1024", "2048"});
            rsaKeyLengthBox.setSelectedItem("2048");
            addRow(card, c, "Public key", wrap(publicKeyField, 96));
            addRow(card, c, "Private key", wrap(privateKeyField, 96));
            addRow(card, c, "Độ dài key", rsaKeyLengthBox);
            addGenerateToggle(card, c);
        }

        if (mode == PanelMode.SIGNATURE) {
            signatureField = createTextArea(4, 60);
            addRow(card, c, "Chữ ký", wrap(signatureField, 96));
        }

        if (mode == PanelMode.HASH || mode == PanelMode.ASYMMETRIC) {
            filePathField = new JTextField();
            filePathField.setEditable(false);
            addRow(card, c, "Tệp", createFilePickerRow());
        }

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        JLabel inputLabel = new JLabel(mode == PanelMode.HASH ? "Dữ liệu cần băm" : "Dữ liệu đầu vào");
        inputLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        card.add(inputLabel, c);

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        card.add(wrap(inputArea, 140), c);

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        JPanel buttonRow = new JPanel();
        buttonRow.setOpaque(false);
        JButton primaryButton = new JButton(primaryButtonText());
        JButton secondaryButton = mode == PanelMode.HASH ? null : new JButton(secondaryButtonText());
        JButton filePrimaryButton = null;
        JButton fileSecondaryButton = null;
        if (mode == PanelMode.HASH) {
            filePrimaryButton = new JButton("Băm file");
        } else if (mode == PanelMode.ASYMMETRIC) {
            filePrimaryButton = new JButton("Mã hóa file");
            fileSecondaryButton = new JButton("Giải mã file");
        }
        JButton clearButton = new JButton("Xóa");
        buttonRow.add(primaryButton);
        if (secondaryButton != null) {
            buttonRow.add(secondaryButton);
        }
        if (filePrimaryButton != null) {
            buttonRow.add(filePrimaryButton);
        }
        if (fileSecondaryButton != null) {
            buttonRow.add(fileSecondaryButton);
        }
        buttonRow.add(clearButton);
        card.add(buttonRow, c);

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        card.add(statusLabel, c);

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        JLabel outputLabel = new JLabel(mode == PanelMode.HASH ? "Kết quả băm" : "Kết quả / ghi chú");
        outputLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        card.add(outputLabel, c);

        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        card.add(wrap(outputArea, 140), c);

        primaryButton.addActionListener(e -> processPrimaryAction());
        if (secondaryButton != null) {
            secondaryButton.addActionListener(e -> processSecondaryAction());
        }
        if (filePrimaryButton != null) {
            filePrimaryButton.addActionListener(e -> processFilePrimaryAction());
        }
        if (fileSecondaryButton != null) {
            fileSecondaryButton.addActionListener(e -> processFileSecondaryAction());
        }
        algorithmBox.addActionListener(e -> refreshHints());
        clearButton.addActionListener(e -> clearFields());

        refreshHints();
        return card;
    }

    private void addGenerateToggle(JPanel card, GridBagConstraints c) {
        gbcAdvance(c);
        c.gridx = 0;
        c.gridwidth = 2;
        card.add(generateKeyCheckBox, c);
        gbcAdvance(c);
    }

    private void processPrimaryAction() {
        try {
            String algorithm = selectedAlgorithm();
            String input = requireInput();

            if (mode == PanelMode.HASH) {
                String hash = hashService.hash(algorithm, input);
                outputArea.setText("Kết quả băm (" + algorithm + ")\n\n" + hash);
                setStatus("Đã băm dữ liệu thành công.", new Color(20, 120, 60));
                return;
            }

            if (mode == PanelMode.SIGNATURE) {
                String privateKey = resolvePrivateKey();
                String signature = digitalSignatureService.sign(algorithm, input, privateKey);
                if (signatureField != null) {
                    signatureField.setText(signature);
                }
                outputArea.setText("Chữ ký số (" + algorithm + ")\n\n" + signature);
                setStatus("Đã ký dữ liệu thành công.", new Color(20, 120, 60));
                return;
            }

            if (mode == PanelMode.ASYMMETRIC) {
                String publicKey = resolvePublicKey();
                String cipherText = asymmetricCryptoService.encrypt(algorithm, input, publicKey);
                outputArea.setText("Kết quả mã hóa RSA\n\n" + cipherText);
                setStatus("Đã mã hóa bằng RSA.", new Color(20, 120, 60));
                return;
            }

            handleSymmetricEncrypt(algorithm, input);
        } catch (IllegalArgumentException ex) {
            handleError(ex.getMessage());
        } catch (Exception ex) {
            handleError("Chương trình gặp lỗi: " + ex.getMessage());
        }
    }

    private void processSecondaryAction() {
        try {
            String algorithm = selectedAlgorithm();
            String input = requireInput();

            if (mode == PanelMode.SIGNATURE) {
                String publicKey = resolvePublicKey();
                String signature = resolveSignature();
                boolean verified = digitalSignatureService.verify(algorithm, input, signature, publicKey);
                outputArea.setText("Xác minh chữ ký (" + algorithm + ")\n\n" + (verified ? "Hợp lệ" : "Không hợp lệ"));
                setStatus(verified ? "Chữ ký hợp lệ." : "Chữ ký không hợp lệ.", verified ? new Color(20, 120, 60) : new Color(170, 50, 40));
                return;
            }

            if (mode == PanelMode.ASYMMETRIC) {
                String privateKey = resolvePrivateKey();
                String plainText = asymmetricCryptoService.decrypt(algorithm, input, privateKey);
                outputArea.setText("Kết quả giải mã RSA\n\n" + plainText);
                setStatus("Đã giải mã bằng RSA.", new Color(20, 120, 60));
                return;
            }

            handleSymmetricDecrypt(algorithm, input);
        } catch (IllegalArgumentException ex) {
            handleError(ex.getMessage());
        } catch (Exception ex) {
            handleError("Chương trình gặp lỗi: " + ex.getMessage());
        }
    }

    private void processFilePrimaryAction() {
        try {
            Path filePath = requireSelectedFilePath();
            String algorithm = selectedAlgorithm();

            if (mode == PanelMode.HASH) {
                String hash = hashService instanceof MessageDigestHashService messageDigestHashService
                        ? messageDigestHashService.hashFile(algorithm, filePath)
                        : hashService.hash(algorithm, Files.readString(filePath));
                outputArea.setText("Kết quả băm file (" + algorithm + ")\nFile: " + filePath + "\n\n" + hash);
                setStatus("Đã băm file thành công.", new Color(20, 120, 60));
                return;
            }

            if (mode == PanelMode.ASYMMETRIC) {
                String publicKey = resolvePublicKey();
                String cipherText = asymmetricCryptoService instanceof RsaCryptoService rsaCryptoService
                        ? rsaCryptoService.encryptFile(algorithm, filePath, publicKey)
                        : asymmetricCryptoService.encrypt(algorithm, Files.readString(filePath), publicKey);
                Path outputFile = createEncryptedOutputFile(filePath);
                Files.writeString(outputFile, cipherText);
                outputArea.setText("Kết quả mã hóa file RSA\nFile gốc: " + filePath + "\nFile đầu ra: " + outputFile + "\n\n" + cipherText);
                setStatus("Đã mã hóa file bằng RSA và lưu ra " + outputFile.getFileName(), new Color(20, 120, 60));
                return;
            }

            throw new IllegalArgumentException("Chế độ file không được hỗ trợ.");
        } catch (IllegalArgumentException ex) {
            handleError(ex.getMessage());
        } catch (Exception ex) {
            handleError("Chương trình gặp lỗi: " + ex.getMessage());
        }
    }

    private void processFileSecondaryAction() {
        try {
            if (mode != PanelMode.ASYMMETRIC) {
                throw new IllegalArgumentException("Chế độ file không được hỗ trợ.");
            }

            Path filePath = requireSelectedFilePath();
            String algorithm = selectedAlgorithm();
            String privateKey = resolvePrivateKey();
                byte[] plainBytes = asymmetricCryptoService instanceof RsaCryptoService rsaCryptoService
                    ? rsaCryptoService.decryptFileBytes(algorithm, filePath, privateKey)
                    : asymmetricCryptoService.decrypt(algorithm, Files.readString(filePath), privateKey).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Path outputFile = createDecryptedOutputFile(filePath);
                Files.write(outputFile, plainBytes);
                outputArea.setText("Kết quả giải mã file RSA\nFile gốc: " + filePath + "\nFile đầu ra: " + outputFile + "\n\nĐã lưu nội dung giải mã ra file.");
            setStatus("Đã giải mã file bằng RSA và lưu ra " + outputFile.getFileName(), new Color(20, 120, 60));
        } catch (IllegalArgumentException ex) {
            handleError(ex.getMessage());
        } catch (Exception ex) {
            handleError("Chương trình gặp lỗi: " + ex.getMessage());
        }
    }

    private void handleSymmetricEncrypt(String algorithm, String input) {
        if (CAESAR_ALGORITHM.equals(algorithm)) {
            Integer shift = resolveShift();
            if (shift == null) {
                throw new IllegalArgumentException("Vui lòng nhập key là số nguyên dương hoặc để trống để hệ thống tự tạo key.");
            }
            String output = caesarCipherService.encrypt(input, shift);
            outputArea.setText("Kết quả mã hóa (Caesar)\nKey dịch: " + shift + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(String.valueOf(shift));
            }
            setStatus("Đã mã hóa Caesar.", new Color(20, 120, 60));
            return;
        }

        if (SUBSTITUTION_ALGORITHM.equals(algorithm)) {
            String key = resolveSubstitutionKey();
            String output = substitutionCipherService.encrypt(input, key);
            outputArea.setText("Kết quả mã hóa (Thay thế)\nKey thay thế: " + key + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa thay thế.", new Color(20, 120, 60));
            return;
        }

        if (AFFINE_ALGORITHM.equals(algorithm)) {
            String key = resolveAffineKey();
            String output = affineCipherService.encrypt(input, key);
            outputArea.setText("Kết quả mã hóa (Affine)\nKey affine: " + key + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa Affine.", new Color(20, 120, 60));
            return;
        }

        if (VIGENERE_ALGORITHM.equals(algorithm)) {
            String key = resolveVigenereKey();
            String output = vigenereCipherService.encrypt(input, key);
            outputArea.setText("Kết quả mã hóa (Vigenere)\nKey keyword: " + key + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa Vigenere.", new Color(20, 120, 60));
            return;
        }

        if (BLOWFISH_ALGORITHM.equals(algorithm) || CAMELLIA_ALGORITHM.equals(algorithm)) {
            String key = resolveBlockKey(algorithm);
            PaddingMode paddingMode = PaddingMode.fromDisplayName((String) paddingModeBox.getSelectedItem());
            String output = blockCipherService.encrypt(algorithm, input, key, paddingMode);
            outputArea.setText("Kết quả mã hóa (" + algorithm + ")\nKey Base64: " + key + "\nChế độ padding: " + paddingMode.getDisplayName() + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa " + algorithm + ".", new Color(20, 120, 60));
            return;
        }

        if (HILL_ALGORITHM.equals(algorithm)) {
            String key = resolveHillKey();
            String output = hillCipherService.encrypt(input, key);
            outputArea.setText("Kết quả mã hóa (Hill)\nKey ma trận: " + key + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa Hill.", new Color(20, 120, 60));
            return;
        }

        if (TRANSPOSITION_ALGORITHM.equals(algorithm)) {
            String key = resolveTranspositionKey();
            String output = transpositionCipherService.encrypt(input, key);
            outputArea.setText("Kết quả mã hóa (Hoán vị)\nKey keyword: " + key + "\n\n" + output);
            if (generateKeyCheckBox.isSelected() && getKeyFieldText().isEmpty()) {
                keyField.setText(key);
            }
            setStatus("Đã mã hóa hoán vị.", new Color(20, 120, 60));
            return;
        }

        throw new IllegalArgumentException("Thuật toán chưa được hỗ trợ.");
    }

    private void handleSymmetricDecrypt(String algorithm, String input) {
        if (CAESAR_ALGORITHM.equals(algorithm)) {
            Integer shift = resolveShift();
            if (shift == null) {
                throw new IllegalArgumentException("Vui lòng nhập key là số nguyên dương hoặc để trống để hệ thống tự tạo key.");
            }
            String output = caesarCipherService.decrypt(input, shift);
            outputArea.setText("Kết quả giải mã (Caesar)\nKey dịch: " + shift + "\n\n" + output);
            setStatus("Đã giải mã Caesar.", new Color(20, 120, 60));
            return;
        }

        if (SUBSTITUTION_ALGORITHM.equals(algorithm)) {
            String key = resolveSubstitutionKey();
            String output = substitutionCipherService.decrypt(input, key);
            outputArea.setText("Kết quả giải mã (Thay thế)\nKey thay thế: " + key + "\n\n" + output);
            setStatus("Đã giải mã thay thế.", new Color(20, 120, 60));
            return;
        }

        if (AFFINE_ALGORITHM.equals(algorithm)) {
            String key = resolveAffineKey();
            String output = affineCipherService.decrypt(input, key);
            outputArea.setText("Kết quả giải mã (Affine)\nKey affine: " + key + "\n\n" + output);
            setStatus("Đã giải mã Affine.", new Color(20, 120, 60));
            return;
        }

        if (VIGENERE_ALGORITHM.equals(algorithm)) {
            String key = resolveVigenereKey();
            String output = vigenereCipherService.decrypt(input, key);
            outputArea.setText("Kết quả giải mã (Vigenere)\nKey keyword: " + key + "\n\n" + output);
            setStatus("Đã giải mã Vigenere.", new Color(20, 120, 60));
            return;
        }

        if (BLOWFISH_ALGORITHM.equals(algorithm) || CAMELLIA_ALGORITHM.equals(algorithm)) {
            String key = resolveBlockKey(algorithm);
            PaddingMode paddingMode = PaddingMode.fromDisplayName((String) paddingModeBox.getSelectedItem());
            String output = blockCipherService.decrypt(algorithm, input, key, paddingMode);
            outputArea.setText("Kết quả giải mã (" + algorithm + ")\nKey Base64: " + key + "\nChế độ padding: " + paddingMode.getDisplayName() + "\n\n" + output);
            setStatus("Đã giải mã " + algorithm + ".", new Color(20, 120, 60));
            return;
        }

        if (HILL_ALGORITHM.equals(algorithm)) {
            String key = resolveHillKey();
            String output = hillCipherService.decrypt(input, key);
            outputArea.setText("Kết quả giải mã (Hill)\nKey ma trận: " + key + "\n\n" + output);
            setStatus("Đã giải mã Hill.", new Color(20, 120, 60));
            return;
        }

        if (TRANSPOSITION_ALGORITHM.equals(algorithm)) {
            String key = resolveTranspositionKey();
            String output = transpositionCipherService.decrypt(input, key);
            outputArea.setText("Kết quả giải mã (Hoán vị)\nKey keyword: " + key + "\n\n" + output);
            setStatus("Đã giải mã hoán vị.", new Color(20, 120, 60));
            return;
        }

        throw new IllegalArgumentException("Thuật toán chưa được hỗ trợ.");
    }

    private void refreshHints() {
        String algorithm = selectedAlgorithm();
        if (mode == PanelMode.SYMMETRIC && keyLengthField != null && keyField != null) {
            if (CAESAR_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("3");
                keyLengthField.setEnabled(true);
                keyField.setToolTipText("Nhập số bước dịch, ví dụ 3 hoặc 13");
            } else if (SUBSTITUTION_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("26");
                keyLengthField.setEnabled(false);
                keyField.setToolTipText("Nhập bảng hoán vị 26 chữ cái, ví dụ QWERTYUIOPASDFGHJKLZXCVBNM");
            } else if (AFFINE_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("2");
                keyLengthField.setEnabled(false);
                keyField.setToolTipText("Nhập key dạng a,b ví dụ 5,8. Nếu để trống, hệ thống tự sinh key hợp lệ.");
            } else if (VIGENERE_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("8");
                keyLengthField.setEnabled(true);
                keyField.setToolTipText("Nhập keyword, ví dụ LEMON. Nếu để trống, hệ thống tự sinh keyword.");
            } else if (BLOWFISH_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("128");
                keyLengthField.setEnabled(true);
                keyField.setToolTipText("Nhập key Base64 hoặc để trống để tự sinh. Độ dài key: 32-448 bit.");
            } else if (CAMELLIA_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("128");
                keyLengthField.setEnabled(true);
                keyField.setToolTipText("Nhập key Base64 hoặc để trống để tự sinh. Camellia hỗ trợ 128/192/256 bit.");
            } else if (HILL_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("4");
                keyLengthField.setEnabled(false);
                keyField.setToolTipText("Nhập ma trận 2x2 dạng a,b,c,d ví dụ 3,3,2,5 hoặc để trống để tự sinh.");
            } else if (TRANSPOSITION_ALGORITHM.equals(algorithm)) {
                keyLengthField.setText("8");
                keyLengthField.setEnabled(true);
                keyField.setToolTipText("Nhập keyword hoán vị, ví dụ SECRET hoặc để trống để tự sinh.");
            }
        }

        if (mode == PanelMode.ASYMMETRIC || mode == PanelMode.SIGNATURE) {
            if (RSA_ALGORITHM.equals(algorithm)) {
                if (rsaKeyLengthBox != null) {
                    rsaKeyLengthBox.setSelectedItem("2048");
                }
            }
            if (publicKeyField != null) {
                publicKeyField.setToolTipText("Dán public key RSA Base64, hoặc để trống và tự tạo key pair.");
            }
            if (privateKeyField != null) {
                privateKeyField.setToolTipText("Dán private key RSA Base64, hoặc để trống và tự tạo key pair.");
            }
        }

        if (mode == PanelMode.HASH) {
            if (keyLengthField != null) {
                keyLengthField.setEnabled(false);
            }
        }
    }

    private Integer resolveShift() {
        String keyText = getKeyFieldText();
        String keyLengthText = keyLengthField == null ? "" : keyLengthField.getText().trim();

        if (!keyText.isEmpty()) {
            try {
                int shift = Integer.parseInt(keyText);
                return shift > 0 ? shift : null;
            } catch (NumberFormatException ex) {
                return null;
            }
        }

        if (generateKeyCheckBox.isSelected()) {
            try {
                int maxShift = keyLengthText.isEmpty() ? 25 : Integer.parseInt(keyLengthText);
                return caesarCipherService.generateShift(maxShift);
            } catch (NumberFormatException ex) {
                return null;
            }
        }

        return null;
    }

    private String resolveSubstitutionKey() {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            return substitutionCipherService.generateKey();
        }
        throw new IllegalArgumentException("Vui lòng nhập key thay thế 26 ký tự hoặc bật tự tạo key.");
    }

    private String resolveAffineKey() {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            return affineCipherService.generateKey();
        }
        throw new IllegalArgumentException("Vui lòng nhập key Affine dạng a,b hoặc bật tự tạo key.");
    }

    private String resolveVigenereKey() {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            int length = 8;
            String lengthText = keyLengthField == null ? "" : keyLengthField.getText().trim();
            if (!lengthText.isEmpty()) {
                try {
                    length = Math.max(1, Integer.parseInt(lengthText));
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Độ dài key Vigenere phải là số nguyên.");
                }
            }
            return vigenereCipherService.generateKey(length);
        }
        throw new IllegalArgumentException("Vui lòng nhập keyword Vigenere hoặc bật tự tạo key.");
    }

    private String resolveBlockKey(String algorithm) {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            int keySize = 128;
            String lengthText = keyLengthField == null ? "" : keyLengthField.getText().trim();
            if (!lengthText.isEmpty()) {
                try {
                    keySize = Integer.parseInt(lengthText);
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Độ dài key phải là số nguyên.");
                }
            }
            return blockCipherService.generateKey(algorithm, keySize);
        }
        throw new IllegalArgumentException("Vui lòng nhập key Base64 hoặc bật tự tạo key.");
    }

    private String resolveHillKey() {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            return hillCipherService.generateKey();
        }
        throw new IllegalArgumentException("Vui lòng nhập key Hill dạng a,b,c,d hoặc bật tự tạo key.");
    }

    private String resolveTranspositionKey() {
        String keyText = getKeyFieldText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            int length = 8;
            String lengthText = keyLengthField == null ? "" : keyLengthField.getText().trim();
            if (!lengthText.isEmpty()) {
                try {
                    length = Math.max(3, Integer.parseInt(lengthText));
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Độ dài key hoán vị phải là số nguyên.");
                }
            }
            return transpositionCipherService.generateKey(length);
        }
        throw new IllegalArgumentException("Vui lòng nhập keyword hoán vị hoặc bật tự tạo key.");
    }

    private String resolvePublicKey() {
        String keyText = getPublicKeyText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            generateRsaKeyPairIfNeeded();
            return getPublicKeyText();
        }
        throw new IllegalArgumentException("Vui lòng nhập public key RSA hoặc bật tự tạo key.");
    }

    private String resolvePrivateKey() {
        String keyText = getPrivateKeyText();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        if (generateKeyCheckBox.isSelected()) {
            generateRsaKeyPairIfNeeded();
            return getPrivateKeyText();
        }
        throw new IllegalArgumentException("Vui lòng nhập private key RSA hoặc bật tự tạo key.");
    }

    private String resolveSignature() {
        String keyText = signatureField == null ? "" : signatureField.getText().trim();
        if (!keyText.isEmpty()) {
            return keyText;
        }
        throw new IllegalArgumentException("Vui lòng nhập chữ ký để xác minh.");
    }

    private void generateRsaKeyPairIfNeeded() {
        if (!getPublicKeyText().isEmpty() && !getPrivateKeyText().isEmpty()) {
            return;
        }

        int keyLength = 2048;
        if (rsaKeyLengthBox != null && rsaKeyLengthBox.getSelectedItem() != null) {
            keyLength = Integer.parseInt(String.valueOf(rsaKeyLengthBox.getSelectedItem()));
        }

        String generated = asymmetricCryptoService.generateKeyPair(RSA_ALGORITHM, keyLength);
        String[] pair = generated.split("\\R", 2);
        if (pair.length != 2) {
            throw new IllegalArgumentException("Không thể tạo key pair RSA hợp lệ.");
        }

        if (publicKeyField != null && getPublicKeyText().isEmpty()) {
            publicKeyField.setText(pair[0]);
        }
        if (privateKeyField != null && getPrivateKeyText().isEmpty()) {
            privateKeyField.setText(pair[1]);
        }
    }

    private String selectedAlgorithm() {
        return String.valueOf(algorithmBox.getSelectedItem());
    }

    private String requireInput() {
        String input = inputArea.getText();
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Vui lòng nhập dữ liệu đầu vào.");
        }
        return input;
    }

    private String getKeyFieldText() {
        return keyField == null ? "" : keyField.getText().trim();
    }

    private String getPublicKeyText() {
        return publicKeyField == null ? "" : publicKeyField.getText().trim();
    }

    private String getPrivateKeyText() {
        return privateKeyField == null ? "" : privateKeyField.getText().trim();
    }

    private void clearFields() {
        inputArea.setText("");
        outputArea.setText("");
        setStatus("Đã xóa dữ liệu.", new Color(68, 79, 99));
        if (keyField != null) {
            keyField.setText("");
        }
        if (publicKeyField != null) {
            publicKeyField.setText("");
        }
        if (privateKeyField != null) {
            privateKeyField.setText("");
        }
        if (signatureField != null) {
            signatureField.setText("");
        }
        if (filePathField != null) {
            filePathField.setText("");
        }
        refreshHints();
    }

    private JComponent createFilePickerRow() {
        JPanel panel = new JPanel(new java.awt.BorderLayout(8, 0));
        panel.setOpaque(false);
        filePathField.setColumns(28);
        JButton browseButton = new JButton("Chọn file");
        browseButton.addActionListener(e -> chooseFile());
        panel.add(filePathField, BorderLayout.CENTER);
        panel.add(browseButton, BorderLayout.EAST);
        return panel;
    }

    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            if (filePathField != null) {
                filePathField.setText(selected.getAbsolutePath());
            }
            setStatus("Đã chọn file: " + selected.getName(), new Color(68, 79, 99));
        }
    }

    private Path requireSelectedFilePath() {
        if (filePathField == null || filePathField.getText().trim().isEmpty()) {
            throw new IllegalArgumentException("Vui lòng chọn một file trước khi thực hiện.");
        }
        return Path.of(filePathField.getText().trim());
    }

    private Path createEncryptedOutputFile(Path inputFile) {
        Path parent = inputFile.toAbsolutePath().getParent();
        String fileName = inputFile.getFileName().toString();
        int lastDot = fileName.lastIndexOf('.');
        String outputName;
        
        if (lastDot > 0) {
            String baseName = fileName.substring(0, lastDot);
            String extension = fileName.substring(lastDot);
            outputName = baseName + ".enc" + extension;
        } else {
            outputName = fileName + ".enc";
        }
        
        return parent == null ? Path.of(outputName) : parent.resolve(outputName);
    }

    private Path createDecryptedOutputFile(Path inputFile) {
        Path parent = inputFile.toAbsolutePath().getParent();
        String fileName = inputFile.getFileName().toString();
        String outputName;

        if (fileName.toLowerCase().contains(".enc.")) {
            outputName = fileName.replace(".enc.", ".dec.");
        } else if (fileName.toLowerCase().endsWith(".enc")) {
            outputName = fileName.substring(0, fileName.length() - 4) + ".dec";
        } else {
            int lastDot = fileName.lastIndexOf('.');
            if (lastDot > 0) {
                String baseName = fileName.substring(0, lastDot);
                String extension = fileName.substring(lastDot);
                outputName = baseName + ".dec" + extension;
            } else {
                outputName = fileName + ".dec";
            }
        }

        return parent == null ? Path.of(outputName) : parent.resolve(outputName);
    }

    private void handleError(String message) {
        setStatus(message, new Color(170, 50, 40));
        outputArea.setText(message);
        JOptionPane.showMessageDialog(this, message, "Lỗi", JOptionPane.ERROR_MESSAGE);
    }

    private void setStatus(String message, Color color) {
        statusLabel.setText(message);
        statusLabel.setForeground(color);
    }

    private String primaryButtonText() {
        if (mode == PanelMode.HASH) {
            return "Băm";
        }
        if (mode == PanelMode.SIGNATURE) {
            return "Ký";
        }
        return "Mã hóa";
    }

    private String secondaryButtonText() {
        if (mode == PanelMode.SIGNATURE) {
            return "Xác minh";
        }
        return "Giải mã";
    }

    private static boolean containsAlgorithm(String[] algorithms, String target) {
        for (String algorithm : algorithms) {
            if (target.equalsIgnoreCase(algorithm.trim())) {
                return true;
            }
        }
        return false;
    }

    private static String initialSymmetricKeyLength(String[] algorithms) {
        if (containsAlgorithm(algorithms, CAESAR_ALGORITHM)) {
            return "3";
        }
        if (containsAlgorithm(algorithms, SUBSTITUTION_ALGORITHM)) {
            return "26";
        }
        if (containsAlgorithm(algorithms, HILL_ALGORITHM)) {
            return "4";
        }
        if (containsAlgorithm(algorithms, TRANSPOSITION_ALGORITHM)) {
            return "8";
        }
        return "128";
    }

    private JTextArea createTextArea(int rows, int columns) {
        JTextArea textArea = new JTextArea(rows, columns);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        return textArea;
    }

    private void addRow(JPanel card, GridBagConstraints c, String labelText, JComponent field) {
        c.gridwidth = 1;
        c.gridx = 0;
        JLabel label = new JLabel(labelText);
        label.setFont(new Font("SansSerif", Font.PLAIN, 14));
        card.add(label, c);

        c.gridx = 1;
        card.add(field, c);
        gbcAdvance(c);
    }

    private void gbcAdvance(GridBagConstraints c) {
        c.gridy++;
    }

    private JComponent wrap(JTextArea area, int height) {
        JScrollPane scrollPane = new JScrollPane(area);
        scrollPane.setPreferredSize(new Dimension(0, height));
        return scrollPane;
    }

    private JComponent createTipCard() {
        JPanel tip = new JPanel();
        tip.setBackground(new Color(247, 249, 252));
        tip.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(223, 229, 238)),
                BorderFactory.createEmptyBorder(14, 16, 14, 16)
        ));
        tip.setLayout(new javax.swing.BoxLayout(tip, javax.swing.BoxLayout.Y_AXIS));

        JLabel label = new JLabel("Lưu ý thiết kế");
        label.setFont(new Font("SansSerif", Font.BOLD, 16));
        label.setForeground(new Color(33, 44, 67));
        JLabel detail = new JLabel(mode == PanelMode.HASH
                ? "Tab hash dùng MessageDigest để băm dữ liệu và trả về chuỗi hex."
                : mode == PanelMode.ASYMMETRIC
            ? "Tab bất đối xứng hỗ trợ RSA, cho phép nhập key có sẵn hoặc tự tạo key pair với độ dài 1024/2048 bit."
                : mode == PanelMode.SIGNATURE
                ? "Tab chữ ký dùng RSA để ký và xác minh chữ ký số với key do người dùng nhập hoặc tự sinh."
                : "Tab đối xứng hỗ trợ key nhập tay hoặc key sinh tự động theo độ dài mong muốn.");
        detail.setFont(new Font("SansSerif", Font.PLAIN, 14));
        detail.setForeground(new Color(68, 79, 99));

        tip.add(label);
        tip.add(javax.swing.Box.createVerticalStrut(6));
        tip.add(detail);
        return tip;
    }
}
