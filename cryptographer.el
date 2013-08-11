;;; cryptographer-el --- Provides functions useful when working on cryptography

;; Copyright (C) 2013 Leo Perrin
;;
;; Author: Leo Perrin <leoperrin at picarresursix dot fr>
;; Created: 2013-08-11
;; Version: 0.1
;; Keywords: cryptography, research
;; URL: https://github.com/picarresursix/cryptographer-el
;; Compatibility: GNU Emacs 24.x
;;
;; This file is NOT part of GNU Emacs.
;;
;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License
;; as published by the Free Software Foundation; either version 2
;; of the License, or (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.


(defun cryptographer/hex-to-binary(hex)
  "Returns a string corresponding to the binary representation of
the hexadecimal string given as an input.

Characters which are not hexadecimal digits are simply ignored.
Example: (cryptographer/hex-to-binary \"0a 0b 4C\")
         \"000010100000101101001100\"
"
  (let (result i c)
    (setq result "")
    (dotimes (i (length hex))
      (setq c (char-to-string (aref hex i)))
      (cond ((string= c "0") (setq result (concat result "0000")))
            ((string= c "1") (setq result (concat result "0001")))
            ((string= c "2") (setq result (concat result "0010")))
            ((string= c "3") (setq result (concat result "0011")))
            ((string= c "4") (setq result (concat result "0100")))
            ((string= c "5") (setq result (concat result "0101")))
            ((string= c "6") (setq result (concat result "0110")))
            ((string= c "7") (setq result (concat result "0111")))
            ((string= c "8") (setq result (concat result "1000")))
            ((string= c "9") (setq result (concat result "1001")))
            ((or (string= c "a") (string= c "A")) (setq result (concat result "1010")))
            ((or (string= c "b") (string= c "B")) (setq result (concat result "1011")))
            ((or (string= c "c") (string= c "C")) (setq result (concat result "1100")))
            ((or (string= c "d") (string= c "D")) (setq result (concat result "1101")))
            ((or (string= c "e") (string= c "E")) (setq result (concat result "1110")))
            ((or (string= c "f") (string= c "F")) (setq result (concat result "1111")))
            ))
    result))




(defun cryptographer/hamming-weight(hex)
  "Returns the hamming weight of the hexadecimel string given as
a parameter. Characters which are not hexadecimal digits are
simply ignored.

Example: (cryptographer/hamming-weight \"0a 0b 4C\")
         8"
  (let (result i c)
    (setq result 0)
    (dotimes (i (length hex))
      (setq c (char-to-string (aref hex i)))
      (cond ((or ; hw = 1
              (string= c "1")
              (string= c "2")
              (string= c "4")
              (string= c "8"))
             (setq result (+ result 1)))
            ((or ; hw = 2
              (string= c "3")
              (string= c "5")
              (string= c "6")
              (string= c "9")
              (string= c "a")
              (string= c "A")
              (string= c "c")
              (string= c "C"))
             (setq result (+ result 2)))
            ((or ; hw = 3
              (string= c "7")
              (string= c "b")
              (string= c "B")
              (string= c "D")
              (string= c "D")
              (string= c "e")
              (string= c "E"))
             (setq result (+ result 3)))
            ((or ; hw = 4
              (string= c "f")
              (string= c "F"))
             (setq result (+ result 4)))
            ))
    result))


(defun cryptographer/apply-hex-operation(hex-operation hex1 hex2)
  "Returns a string corresponding to the hexadecimal
representation of the result of applying operation on byte-wise
on the hexadecimal numbers represented by the input strings.

If the strings are of different length, the smallest is padded
with zeros to its left.
Example: (cryptographer/apply-hex-operation logxor \"0a 0b 4C\" \"e266\")"
  (let (n1 n2 result i index1 index2 c1 c2)
    ; Stripping non hexadeximal digits from inputs
    (setq n1 '())
    (dotimes (i (length hex1))
      (setq c (aref hex1 i))
      (if (or
           (and (>= c ?0) (<= c ?9))
           (and (>= c ?a) (<= c ?f))
           (and (>= c ?A) (<= c ?F)))
          (setq n1 (nconc n1 (list (string-to-int (char-to-string c) 16))))))
    (setq n2 '())
    (dotimes (i (length hex2))
      (setq c (aref hex2 i))
      (if (or
           (and (>= c ?0) (<= c ?9))
           (and (>= c ?a) (<= c ?f))
           (and (>= c ?A) (<= c ?F)))
          (setq n2 (nconc n2 (list (string-to-int (char-to-string c) 16))))))
    ; Computing actual xor
    (setq result "")
    (dotimes (i (max (length n1) (length n2)))
      (setq index1 (- (length n1) i 1))
      (setq index2 (- (length n2) i 1))
      (if (< index1 0)
          (setq c1 0)
        (setq c1 (nth index1 n1)))
      (if (< index2 0)
          (setq c2 0)
        (setq c2 (nth index2 n2)))
      (setq result (concat
                    (format "%x" (funcall hex-operation c1 c2))
                    result)))
    result))


(defun cryptography/insert-spaces()
  (interactive)
  (if (region-active-p)
      (progn
        (let (i begin end)
          (setq begin (region-beginning) end (region-end))
          (goto-char begin)
          (dotimes (i (- end begin))
            (forward-char)
            (if (and (= (mod i 4) 0) (/= i 0))
                (insert " ")))
          (selected-frame)))))


;; (defun cryptographer/left-shift(hex s)
;;   "Returns the result of a bit shift of the hexadecimal string
;; hex by s to the left.

;; Example: (cryptographer/left-shift(\"0010a\" 1))
;;          002110"
;;   (let (i result)
;;     (setq result "")
;;     (dotimes (i (- (length hex) 1))
;;       (setq result (concat
;;                     result
;;                     (format "%x"
;;                             (logior
;;                              (string-to-int (char-to-string (lsh (aref hex i) s)))
;;                              (string-to-int (char-to-string (lsh (aref hex (+ i 1)) (- 4 s))))
;;                              )))))
;;     result))


;; (cryptographer/left-shift "0010a" 1)


(defun cryptography/C-style-array()
  "Inserts spaces, commas and '0x' in the highlighted string to
make it usable as a C-style array of int8_t definition.

Example: 012345 M-x cryptography/C-style-array
         {0x01, 0x23, 0x45};"
  (interactive)
  (if (region-active-p)
      (progn
        (let (i begin end)
          (setq begin (region-beginning) end (region-end))
          (goto-char begin)
          (insert "{0x")
          (dotimes (i (- end begin))
            (if (and (= (mod i 2) 0)
                     (/= i 0)
                     (/ i (- end begin 2))
                     (/ i (- end begin 3)))
                (insert ", 0x"))
            (forward-char))
          (insert "};")
          (selected-frame)))))



(cryptographer/hex-to-binary (cryptographer/apply-hex-operation 'logior "0a0b4c" "e286"))
