package com.vivokey.smartpgp;

import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class TarPIN extends OwnerPIN {
	byte[] shatemp;
	byte[] shatemp2;
	MessageDigest sha224;
	RandomData rand;

	public TarPIN(byte tryLimit, byte maxPINSize) throws PINException {
		super(tryLimit, maxPINSize);
		shatemp = JCSystem.makeTransientByteArray((short) 28, JCSystem.CLEAR_ON_RESET);
		shatemp2 = JCSystem.makeTransientByteArray((short)28, JCSystem.CLEAR_ON_RESET);
		rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		sha224 = MessageDigest.getInstance(MessageDigest.ALG_SHA_224, false);
		
	}
	
	public boolean check(byte[] pin, short offset, byte length) {
		if(super.getTriesRemaining() >= 1) {
			rand.generateData(shatemp, (short)0, (short) 28);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			super.resetAndUnblock();
		}
		return super.check(pin, offset, length);
	}

}
