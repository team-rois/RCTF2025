{-# LANGUAGE LambdaCase #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use <$>" #-}

import Control.Applicative
import Data.Bits (xor, shiftR, (.&.), rotateL, popCount)
import Data.Char (isDigit, isLower, ord)
import Data.Word (Word8, Word64)

-- Tiny parser combinator setup borrowed from chall1.
newtype Parser a = P (String -> [(a, String)])

parse :: Parser a -> String -> [(a, String)]
parse (P p) = p

item :: Parser Char
item = P (\case
            []     -> []
            x : xs -> [(x, xs)])

instance Functor Parser where
    fmap g p = P $ \inp -> case parse p inp of
        []        -> []
        [(x, xs)] -> [(g x, xs)]

instance Applicative Parser where
    pure v = P $ \inp -> [(v, inp)]
    pg <*> px = P $ \inp -> case parse pg inp of
        []        -> []
        [(g, xs)] -> parse (fmap g px) xs

instance Monad Parser where
    p >>= f = P $ \inp -> case parse p inp of
        []        -> []
        [(x, xs)] -> parse (f x) xs

instance Alternative Parser where
    empty = P (const [])
    a <|> b = P $ \inp -> case parse a inp of
        []        -> parse b inp
        [(x, xs)] -> [(x, xs)]

sat :: (Char -> Bool) -> Parser Char
sat t = do
    x <- item
    if t x then pure x else empty

charP :: Char -> Parser Char
charP = sat . (==)

stringP :: String -> Parser String
stringP [] = pure []
stringP (x : xs) = do
    charP x
    stringP xs
    pure (x : xs)

sepBy1 :: Parser a -> Parser sep -> Parser [a]
sepBy1 p sep = (:) <$> p <*> many (sep *> p)

segmentP :: Parser String
segmentP = some $ sat allowed
  where
    allowed c = isLower c || isDigit c || c == '?'

flagParser :: Parser [String]
flagParser = do
    stringP "RCTF{"
    segs <- sepBy1 segmentP (charP '_')
    charP '}'
    pure segs

segmentSalts :: [Word64]
segmentSalts = map fromIntegral [0x11, 0x23, 0x51, 0x8f, 0x133, 0x207, 0x2f1, 0x3b9, 0x44d]

segmentTargets :: [Word64]
segmentTargets =
    [ 0x2c66650f26a2d
    , 0x02db3514
    , 0x34e39ba0f93
    , 0x5d5bd841689
    , 0x321c0396f
    , 0x02a5b7e6b
    , 0x7ae89b0ab
    , 0x26e3141c2d7d
    , 0x059db5eec
    ]

segmentHash :: Word64 -> String -> Word64
segmentHash salt = foldl' step (salt * 1337) . map (fromIntegral . ord)
  where
    step acc ch =
        let rotated = rotateL acc 5
            mixed = rotated `xor` (ch + salt)
            saltInt = fromIntegral salt :: Int
            ones = fromIntegral (popCount ch * (saltInt + 3))
        in mixed + ones

validateSegments :: [String] -> Bool
validateSegments segs =
    length segs == length segmentTargets
        && and (zipWith check segs (zip segmentSalts segmentTargets))
  where
    check seg (salt, target) = segmentHash salt seg == target

permTable :: [Int]
permTable =
    [ 7, 34, 10, 25, 28, 43, 24, 20
    , 4, 11, 23, 19, 22, 46, 41, 27
    , 31, 9, 36, 5, 45, 16, 29, 2
    , 14, 44, 1, 6, 33, 13, 12, 26
    , 17, 47, 21, 15, 39, 40, 3, 30
    , 38, 32, 42, 8, 18, 0, 35, 37
    ]

applyPerm :: [Int] -> [a] -> [a]
applyPerm perm xs = map (xs !!) perm

permuteFlag :: String -> Maybe String
permuteFlag s
    | length s /= length permTable = Nothing
    | otherwise = Just (applyPerm permTable s)

stringToBytes :: String -> [Word8]
stringToBytes = map (fromIntegral . ord)

genKey :: Word8 -> Int -> [Word8]
genKey seed len = take len $ tail $ iterate step seed
  where
    step cur =
        let curInt = fromIntegral cur :: Int
            nxt = (curInt * 73 + 41) `mod` 256
        in fromIntegral nxt

xorBytes :: [Word8] -> [Word8] -> [Word8]
xorBytes = zipWith xor

mirrorXor :: [Word8] -> [Word8]
mirrorXor xs = zipWith xor xs (reverse xs)

byteToBits :: Word8 -> [Word64]
byteToBits b = [fromIntegral ((b `shiftR` i) .&. 1) | i <- [7, 6 .. 0]]

bytesToBits :: [Word8] -> [Word64]
bytesToBits = concatMap byteToBits

weights :: [Word64]
weights =
    [ 1, 2, 34, 79, 133, 281, 586, 1122, 2287, 4540, 9100, 18205, 36386
    , 72772, 145555, 291086, 582206, 1164447, 2328896, 4657771, 9315492
    , 18631038, 37262098, 74524142, 149048324, 298096653, 596193277
    , 1192386547, 2384773139, 4769546232, 9539092446, 19078184934
    , 38156369871, 76312739689, 152625479378, 305250958783, 610501917611
    , 1221003835179, 2442007670348, 4884015340680, 9768030681384
    , 19536061362793, 39072122725535, 78144245451066, 156288490902138
    , 312576981804286, 625153963608581, 1250307927217147, 2500615854434348
    , 5001231708868635, 10002463417737300, 20004926835474570
    , 40009853670949156, 80019707341898319, 160039414683796612
    , 320078829367593255
    ]

targetSums :: [Word64]
targetSums =
    [ 587402602269573142
    , 578736506679249877
    , 204734138181229821
    , 204764191273658563
    , 578919288078391753
    , 585751509696249757
    , 267927837082716025
    ]

computeKnapsackSums :: [Word64] -> [Word64] -> [Word64]
computeKnapsackSums ws bits = map (sum . zipWith (*) ws) (chunksOf 56 bits)

chunksOf :: Int -> [a] -> [[a]]
chunksOf n xs
    | n <= 0    = error "chunksOf: chunk size must be positive"
    | null xs   = []
    | otherwise = take n xs : chunksOf n (drop n xs)

deriveGuardByte :: [String] -> Word8
deriveGuardByte segs = fromIntegral $ foldl' step 0 (map length segs)
  where
    step acc l = (acc * 7 + l) `mod` 256

finalCheck :: [String] -> String -> Bool
finalCheck segs input = case permuteFlag input of
    Nothing        -> False
    Just permuted  ->
        let bytes = stringToBytes permuted
            key = genKey 0xAC (length bytes)
            xored = xorBytes bytes key
            added = map (+ 0x3d) xored
            mirrored = mirrorXor added
            bits = bytesToBits mirrored
            guardBits = byteToBits (deriveGuardByte segs)
            finalBits = bits ++ guardBits
        in computeKnapsackSums weights finalBits == targetSums

simpleChecksum :: String -> Int
simpleChecksum = foldl' step 0 . zip [1 ..]
  where
    step acc (idx, ch) = acc `xor` (ord ch * idx)

validateFlag :: String -> Bool
validateFlag input = case parse flagParser input of
    [(segments, "")] ->
        validateSegments segments
            && finalCheck segments input
            && simpleChecksum input == 1209
    _ -> False

main :: IO ()
main = do
    putStrLn "Reverse me, maybe?"
    candidate <- getLine
    if validateFlag candidate
        then putStrLn "Correct!"
        else putStrLn "Nope."
