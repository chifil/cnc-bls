package bls

import (
	"fmt"
	"reflect"
	"testing"
)

func TestCheckMnemonic(t *testing.T) {
	type args struct {
		mnemonic string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test1",
			args: args{mnemonic: "helmet speed risk tragic silver fetch mutual fit truly spike glare hockey skate candy grunt few tenant regular appear elevator deer mix bonus maple"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMnemonic(tt.args.mnemonic); got != tt.want {
				t.Errorf("CheckMnemonic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMnemonicToEntropy(t *testing.T) {
	type args struct {
		mnemonic string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test1",
			args: args{
				"helmet speed risk tragic silver fetch mutual fit truly spike glare hockey skate candy grunt few tenant regular appear elevator deer mix bonus maple",
			},
			want: []byte{106, 250, 34, 233, 243, 124, 140, 170, 164, 138, 190, 233, 122, 57, 139, 54, 60, 160, 66, 153, 202, 172, 223, 22, 152, 42, 35, 243, 149, 28, 6, 92},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MnemonicToEntropy(tt.args.mnemonic); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MnemonicToEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewMnemonic(t *testing.T) {
	type args struct {
		entropy []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				[]byte{106, 250, 34, 233, 243, 124, 140, 170, 164, 138, 190, 233, 122, 57, 139, 54, 60, 160, 66, 153, 202, 172, 223, 22, 152, 42, 35, 243, 149, 28, 6, 92},
			},
			want:    "helmet speed risk tragic silver fetch mutual fit truly spike glare hockey skate candy grunt few tenant regular appear elevator deer mix bonus maple",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMnemonic(tt.args.entropy)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewMnemonic() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSeed(t *testing.T) {
	type args struct {
		mnemonic string
		password string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test1",
			args: args{
				mnemonic: "helmet speed risk tragic silver fetch mutual fit truly spike glare hockey skate candy grunt few tenant regular appear elevator deer mix bonus maple",
				password: "",
			},
			want: []byte{251, 174, 113, 53, 205, 41, 191, 216, 11, 26, 14, 210, 155, 129, 109, 8, 179, 218, 183, 175, 141, 105, 42, 160, 115, 24, 49, 39, 66, 41, 242, 247, 8, 207, 139, 44, 80, 18, 245, 24, 49, 167, 97, 47, 231, 11, 200, 51, 182, 22, 206, 16, 54, 199, 144, 124, 233, 4, 219, 57, 150, 195, 190, 210},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSeed(tt.args.mnemonic, tt.args.password); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSeed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMnemonic(t *testing.T) {
	entropy, _ := NewEntropy()
	fmt.Println(entropy)
	mnemonic, _ := NewMnemonic(entropy)
	fmt.Println(mnemonic)
	seed := NewSeed(mnemonic, "")
	fmt.Printf("%x\n %v \n", seed, seed)
}
