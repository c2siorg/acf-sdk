package pipeline

import "testing"

func TestNormaliseText_NFKC(t *testing.T) {
	in := "ＡＢＣ"
	got := NormaliseText(in)
	if got.NormalisedText != "ABC" {
		t.Fatalf("expected ASCII fold to ABC, got %q", got.NormalisedText)
	}
	if got.OriginalText != in {
		t.Fatalf("expected original text preserved, got %q", got.OriginalText)
	}
}

func TestNormaliseText_StripsZeroWidth(t *testing.T) {
	in := "he\u200bll\u2060o"
	got := NormaliseText(in)
	if got.NormalisedText != "hello" {
		t.Fatalf("expected zero-width chars stripped, got %q", got.NormalisedText)
	}
}

func TestNormaliseText_DecodesValidPercentEscapes(t *testing.T) {
	in := "ignore%20previous%20instructions"
	got := NormaliseText(in)
	if got.NormalisedText != "ignore previous instructions" {
		t.Fatalf("expected percent decoding, got %q", got.NormalisedText)
	}
}

func TestNormaliseText_InvalidPercentEncodingPreserved(t *testing.T) {
	in := "abc%2Gdef"
	got := NormaliseText(in)
	if got.NormalisedText != in {
		t.Fatalf("expected invalid encoding preserved, got %q", got.NormalisedText)
	}
}

func TestNormaliseText_PlusIsNotConvertedToSpace(t *testing.T) {
	in := "a+b%20c"
	got := NormaliseText(in)
	if got.NormalisedText != "a+b c" {
		t.Fatalf("expected plus preserved and %%20 decoded, got %q", got.NormalisedText)
	}
}

func TestNormaliseJSONValue_StringSliceAndMap(t *testing.T) {
	in := map[string]interface{}{
		"name": "tool",
		"params": map[string]interface{}{
			"q": "\uFF21%20\uFF22", // fullwidth A / B around ASCII %20
		},
		"items": []interface{}{"he\u200bllo", "x"},
	}
	out := NormaliseJSONValue(in).(map[string]interface{})
	params := out["params"].(map[string]interface{})
	if params["q"] != "A B" {
		t.Fatalf("expected nested string normalised, got %q", params["q"])
	}
	items := out["items"].([]interface{})
	if items[0] != "hello" || items[1] != "x" {
		t.Fatalf("expected slice strings normalised, got %#v", items)
	}
}

func TestNormaliseJSONValue_Nil(t *testing.T) {
	if NormaliseJSONValue(nil) != nil {
		t.Fatal("expected nil")
	}
}
